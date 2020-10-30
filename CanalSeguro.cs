using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    // Clase base de las clases que preparan los mensajes
    internal class MensajeBase {


        #region variables privadas

        // instancias que están usando este mensaje;
        protected Seguridad seguridad;
        protected Conexion  conexion;

        //  Mensaje a enviar.
        //      buzón:
        //          +---+---+---+---------------+
        //          | b | i | l |               |
        //          +---+---+---+---------------+
        //      porciones:
        //          b: billete
        //          i: indice
        //          l: longitud

        protected const int bytes_billete  = sizeof (long);
        protected const int bytes_indice   = sizeof (int);
        protected const int bytes_longitud = sizeof (int);
        protected const int bytes_cabecera = bytes_billete + bytes_indice + bytes_longitud; 

        protected Buzon buzon_billete;
        protected Buzon buzon_indice;
        protected Buzon buzon_longitud;

        #endregion


        protected MensajeBase (Seguridad seguridad_) {
            this.seguridad = seguridad_;
            this.conexion  = seguridad_.Conexion;
            //
            buzon_billete  = new Buzon ();
            buzon_indice   = new Buzon ();
            buzon_longitud = new Buzon ();
        }


        protected void PreparaCabecera (Buzon buzon_mensaje) {
            int inicio_billete  = 0;
            int inicio_indice   = bytes_billete;
            int inicio_longitud = bytes_billete + bytes_indice;
            buzon_mensaje.ConstruyePorcion (inicio_billete,  bytes_billete,  buzon_billete);
            buzon_mensaje.ConstruyePorcion (inicio_indice,   bytes_indice,   buzon_indice);
            buzon_mensaje.ConstruyePorcion (inicio_longitud, bytes_longitud, buzon_longitud);
        }


    }


    // Clase que prepara el primer mensajes de establecimiento de secreto. Encriptado con RSA.
    internal sealed class PrimerMensajeClaves : MensajeBase {


        #region variables privadas

        //  Mensaje a encriptar. 
        //      buzón 'texto':
        //          +---+---+
        //          | s | p |
        //          +---+---+
        //      porciones de 'texto':
        //          s: secreto
        //          p: protocolo (dos bytes por caracter)
        //
        //  Mensaje a enviar. 
        //      buzón 'mensaje':
        //          +---+---+---+-------+
        //          | b | i | l |   c   |
        //          +---+---+---+-------+
        //      porciones de 'mensaje':
        //          b: billete
        //          i: indice
        //          l: longitud
        //          c: cifrado (de texto)

        private const int bytes_secreto   = Seguridad.longitud_secreto;
        private       int bytes_protocolo;
        private       int bytes_texto;

        private Buzon buzon_texto;
        private Buzon buzon_secreto;
        private Buzon buzon_protocolo;

        private const int bytes_cifrado = CifradoRSA.BytesEncriptado;
        private const int bytes_mensaje = bytes_cabecera + bytes_cifrado;
            
        private Buzon buzon_mensaje;
        private Buzon buzon_cifrado;

        #endregion


        internal PrimerMensajeClaves (Seguridad seguridad_) : 
                base (seguridad_) {
            Depuracion.Asevera (! seguridad_.DeServidor);
            //
            Prepara ();
        }


        // prepara los buzones
        private void Prepara () {
            bytes_protocolo  = Seguridad.protocolo.Longitud;
            bytes_texto      = bytes_secreto + bytes_protocolo;
            //
            buzon_texto     = new Buzon ();
            buzon_secreto   = new Buzon ();
            buzon_protocolo = new Buzon ();
            //
            buzon_texto.Reserva (bytes_texto);
            buzon_texto.ConstruyePorcion (            0, bytes_secreto,   buzon_secreto);
            buzon_texto.ConstruyePorcion (bytes_secreto, bytes_protocolo, buzon_protocolo);
            //
            buzon_mensaje = new Buzon ();
            buzon_cifrado = new Buzon ();
            //
            buzon_mensaje.Reserva (bytes_mensaje);
            PreparaCabecera (buzon_mensaje);
            buzon_mensaje.ConstruyePorcion (bytes_cabecera,  bytes_cifrado,  buzon_cifrado);
        }


        // envia el mensaje (desde el servicio)
        internal void Envia (Buzon secreto_) {
            Buzon.CopiaDatos (secreto_, this.buzon_secreto);
            Buzon.CopiaDatos (Seguridad.protocolo, this.buzon_protocolo);
            buzon_billete .PonInt (0, 0);
            buzon_indice  .PonInt (0, 0);
            buzon_longitud.PonInt (0, buzon_mensaje.Longitud);
            //
            CifradoRSA cifrado_RSA = new CifradoRSA ();
            try {
                cifrado_RSA.IniciaPublica (seguridad.clave_publica);
                cifrado_RSA.CifraPublica (buzon_texto, buzon_cifrado);
            } finally { 
                cifrado_RSA.Termina ();
            } 
            //
            conexion.EnviaSocket (buzon_mensaje, buzon_mensaje.Longitud);
            //
//            seguridad.ImprimeEnvia (billete, indice, longitud, "RSA ( S1 | protocolo )");
        }


        // recibe el mensaje (en el cliente)
        internal void Recibe (out Buzon secreto_) {
            conexion.RecibeSocket (buzon_mensaje, 0, buzon_mensaje.Longitud);
            //
//            seguridad.ImprimeRecibe (billete, indice, longitud, "RSA ( S1 | protocolo )");
            //
            // se valida el mensaje
            if (buzon_billete .TomaInt (0) != 0 ||
                buzon_indice  .TomaInt (0) != 0 ||
                buzon_longitud.TomaInt (0) != buzon_mensaje.Longitud) {
                throw new ErrorConexion ("Violación del protocolo de seguridad.");
            }
            //
            CifradoRSA cifrado_RSA = new CifradoRSA ();
            try {
                cifrado_RSA.IniciaPrivada (seguridad.seguridad_servidor.clave_privada);
                cifrado_RSA.DescifraPrivada (buzon_cifrado, buzon_texto);
            } finally { 
                cifrado_RSA.Termina ();
            }
            //
            if (! Buzon.DatosIguales (this.buzon_protocolo, Seguridad.protocolo)) {
                throw new ErrorConexion ("Protocolo de seguridad inconsistente.");
            }
            //
            secreto_ = this.buzon_secreto;
        }


    }


    // Clase base de preparación de los mensajes encriptados con AES.
    internal class MensajeSimetrico : MensajeBase {


        #region variables protegidas

        //  Mensaje a enviar.
        //      buzón:
        //          +---+---+---+-----------+---+
        //          | b | i | l |     d     | a |
        //          +---+---+---+-----------+---+
        //      porción 'sensible':
        //          +---+---+---+-----------+ · ·
        //          | b | i | l |     d     |   ·
        //          +---+---+---+-----------+ · ·
        //      porción 'cifrado':       
        //          · · · · · · +-----------+---+
        //          ·           |     d     | a |
        //          · · · · · · +-----------+---+
        //      porciones:
        //          b: billete
        //          i: indice
        //          l: longitud
        //          d: datos
        //          a: autentica

        protected const int bytes_autentica = CalculoHMAC.BytesValor;
        protected       int bytes_sensible;
        protected       int bytes_cifrado;

        protected Buzon buzon_autentica;
        protected Buzon buzon_sensible;
        protected Buzon buzon_cifrado;

        #endregion


        internal MensajeSimetrico (Seguridad seguridad_) : 
                base (seguridad_) {
            buzon_autentica = new Buzon ();
            buzon_sensible  = new Buzon ();
            buzon_cifrado   = new Buzon ();
        }


        protected void PreparaGrupos (Buzon buzon_mensaje, int bytes_datos) {
            bytes_sensible = bytes_cabecera + bytes_datos;
            bytes_cifrado =  bytes_datos + bytes_autentica;
            //            
            int inicio_sensible  = 0;
            int inicio_cifrado   = bytes_cabecera;
            int inicio_autentica = bytes_cabecera + bytes_datos;
            //
            buzon_mensaje.ConstruyePorcion (inicio_sensible,  bytes_sensible,  buzon_sensible); 
            buzon_mensaje.ConstruyePorcion (inicio_cifrado,   bytes_cifrado,   buzon_cifrado);
            buzon_mensaje.ConstruyePorcion (inicio_autentica, bytes_autentica, buzon_autentica);
        }

        internal void AutenticaCifra () {
        }


        internal void DescifraVerifica () {
        }


    }


    // Clase que prepara un mensaje del protocolo de seguridad (establecimiento de clave o de 
    // billete). 
    // Hay algunas variantes de este mensaje, según el contenido.
    // Derivada de 'MensajeSimetrico' por ser encriptados con AES.
    // 
    internal sealed class MensajeSeguridad : MensajeSimetrico {


        #region variables privadas

        //  Mensaje a enviar.
        //      buzón 'mensaje':
        //          +---+---+---+---+---+---+---+
        //          | b | i | l | c | n | p | a |
        //          +---+---+---+---+---+---+---+
        //      porción 'sensible':
        //          +---+---+---+---+---+---+ · ·
        //          | b | i | l | c | n | p |   ·
        //          +---+---+---+---+---+---+ · ·
        //      porción 'cifrado':       
        //          · · · · · · +---+---+---+---+
        //          ·           | c | n | p | a |
        //          · · · · · · +---+---+---+---+
        //      porciones:
        //          b: billete
        //          i: indice
        //          l: longitud
        //          c: clave
        //          n: numero
        //          p: protocolo
        //          a: autentica
        //      observación:
        //          clave, numero y protocolo pueden ser vacíos.

        private int bytes_clave;
        private int bytes_numero;
        private int bytes_protocolo;
        private int bytes_datos;
        private int bytes_mensaje;

        private Buzon buzon_mensaje;
        private Buzon buzon_clave;
        private Buzon buzon_numero;
        private Buzon buzon_protocolo;

        // otros buzones en el base

        #endregion


        internal MensajeSeguridad (Seguridad seguridad_) :
                base (seguridad_) {
            Prepara ();
        }


        private void Prepara () {
            bytes_clave     = 0;
            bytes_numero    = 0;
            bytes_protocolo = 0;
            if (true) {
                bytes_clave     = Seguridad.longitud_secreto;
            }
            if (true) {
                bytes_numero    = bytes_billete;
            }
            if (true) {
                bytes_protocolo = Seguridad.protocolo.Longitud;
            }
            bytes_datos   = bytes_clave + bytes_numero + bytes_protocolo;
            bytes_mensaje = bytes_cabecera + bytes_datos + bytes_autentica;
            //
            buzon_mensaje   = new Buzon ();
            buzon_clave     = new Buzon ();
            buzon_numero    = new Buzon ();
            buzon_protocolo = new Buzon ();
            //
            int inicio_clave     = bytes_cabecera;
            int inicio_numero    = inicio_clave  + bytes_clave;
            int inicio_protocolo = inicio_numero + bytes_numero;
            //
            buzon_mensaje.Reserva (bytes_mensaje);
            PreparaCabecera (buzon_mensaje);
            if (true) {
                buzon_mensaje.ConstruyePorcion (inicio_clave,     bytes_clave,     buzon_clave);
            }
            if (true) {
                buzon_mensaje.ConstruyePorcion (inicio_numero,    bytes_numero,    buzon_numero);
            }
            if (true) {
                buzon_mensaje.ConstruyePorcion (inicio_protocolo, bytes_protocolo, buzon_protocolo);
            }
            PreparaGrupos (buzon_mensaje, bytes_datos);
        }


        internal long Recibe () {
            throw new NotImplementedException ();
        }


        internal void Envia (long billete) {
            throw new NotImplementedException ();
        }


    }


    // Clase que prepara los mensajes generales de envío y recepción de datos. Derivada de 
    // 'MensajeSimetrico' por ser encriptados con AES.
    // 
    internal sealed class MensajeGeneral : MensajeSimetrico {


        #region variables privadas

        //  Mensaje a enviar.
        //      buzón 'Conexion.BuzonMensaje':
        //          +---+---+---+-----------+---+-----+
        //          | b | i | l |     p     | a |     |
        //          +---+---+---+-----------+---+-----+
        //      porción 'sensible':
        //          +---+---+---+-----------+ · · · · ·
        //          | b | i | l |     p     |         ·
        //          +---+---+---+-----------+ · · · · ·
        //      porción 'cifrado':       
        //          · · · · · · +-----------+---+ · · ·
        //          ·           |     p     | a |     ·
        //          · · · · · · +-----------+---+ · · ·
        //      porciones:
        //          b: billete
        //          i: indice
        //          l: longitud
        //          p: 'Conexion.BuzonPaquete'
        //          a: autentica
        //      observación:
        //          posible parte final del mensaje no usada

        private int bytes_paquete;
        private int bytes_mensaje;

        #endregion


        internal MensajeGeneral (Seguridad seguridad_) :
                base (seguridad_) {
        }


        internal void PreparaBuzones (int longitud_paquete) {  
            bytes_paquete = longitud_paquete;
            bytes_mensaje = bytes_cabecera + bytes_paquete + bytes_autentica;
            //
            if (conexion.BuzonMensaje.Longitud == 0) {
			    conexion.BuzonMensaje.Reserva (bytes_mensaje);
                ConstruyeBuzones ();
			    return;
		    }
		    if (conexion.BuzonMensaje.Longitud < bytes_mensaje) {
                AnulaBuzones ();
                Buzon nuevo = new Buzon ();
                nuevo.Reserva (bytes_mensaje);
			    //if (conexion.paquete_entrada || 
       //             conexion.paquete_salida    ) {
                    Buzon.CopiaDatos (conexion.BuzonMensaje, nuevo, conexion.BuzonMensaje.Longitud);
			    //}
                conexion.BuzonMensaje.TrasponBuzon (nuevo);
                ConstruyeBuzones ();
                return;
		    }
            ReestableceBuzones ();
        }


        private void ConstruyeBuzones () {
            PreparaCabecera (conexion.BuzonMensaje);
            conexion.BuzonMensaje.ConstruyePorcion (bytes_cabecera, bytes_paquete, conexion.BuzonPaquete);
            PreparaGrupos (conexion.BuzonMensaje, bytes_paquete);
        }


        private void AnulaBuzones () {
            conexion.BuzonMensaje.AnulaPorcion (buzon_billete);
            conexion.BuzonMensaje.AnulaPorcion (buzon_indice);
            conexion.BuzonMensaje.AnulaPorcion (buzon_longitud);
            conexion.BuzonMensaje.AnulaPorcion (conexion.BuzonPaquete);
            conexion.BuzonMensaje.AnulaPorcion (buzon_autentica);
            conexion.BuzonMensaje.AnulaPorcion (buzon_sensible);
            conexion.BuzonMensaje.AnulaPorcion (buzon_cifrado);
        }


        private void ReestableceBuzones () {
            int medida = bytes_paquete - conexion.BuzonPaquete.Longitud;
            conexion.BuzonMensaje.RedimensionaPorcion (conexion.BuzonPaquete, medida);
            conexion.BuzonMensaje.ResituaPorcion      (buzon_autentica,       medida);
            conexion.BuzonMensaje.RedimensionaPorcion (buzon_sensible,        medida);
            conexion.BuzonMensaje.RedimensionaPorcion (buzon_cifrado,         medida);
        }


        internal void Envia () {
            buzon_billete .PonLong (0, seguridad.contador_CTR_local.NumeroSerie);  
            buzon_indice  .PonInt  (0, seguridad.contador_CTR_local.NumeroMensaje);
            buzon_longitud.PonInt  (0, bytes_mensaje);
            //
            base.AutenticaCifra ();
            //
            conexion.EnviaSocket (conexion.BuzonMensaje, bytes_mensaje);
            //
            //seguridad.ImprimeEnvia (this.billete, this.indice, this.longitud, "AES ( t | a )");
       }


        internal void Recibe () {
            conexion.RecibeSocket (conexion.BuzonMensaje, 0, bytes_cabecera);
            //
            // se valida el mensaje
            if (buzon_billete .TomaLong (0) != seguridad.contador_CTR_remoto.NumeroSerie   ||
                buzon_indice  .TomaInt  (0) != seguridad.contador_CTR_remoto.NumeroMensaje   ) {
                // ¿que hacer????
                return;
            }
            //
            // validar resto:
            int bytes_resto   = buzon_longitud.TomaInt (0) - bytes_cabecera;
            int bytes_paquete = bytes_resto - bytes_autentica;
            //
            PreparaBuzones (bytes_paquete);
            //
            conexion.RecibeSocket (conexion.BuzonMensaje, bytes_cabecera, bytes_resto);
            //
            //seguridad.ImprimeRecibe (buzon_billete, buzon_indice, buzon_longitud, "AES ( t | a )");
            //
            base.DescifraVerifica ();       
        }


    }


    internal sealed class Seguridad {


        #region variables y constantes internas y privadas 

        // el cliente envia al servidor un valor secreto a partir del cual se crean las dos claves 
        // de encriptación y las dos de autenticación, este valor secreto es de 32 bytes
        internal const int longitud_secreto = 32;

        // el cliente envia al servidor un literal que indica el protocolo de seguridad que se está
        // usando, el servidor valida que coincidan
        static internal Buzon protocolo;

        // es la instancia que contiene a esta
        private Conexion conexion;

        // indica que se ha activado esta seguridad
        private bool activa;
        // indica con que papel se ha activado esta seguridad
        private bool de_servidor; 
		private bool de_servicio;
		private bool de_cliente;

        // almacena la clave privada, solo en servidor
        internal Buzon clave_privada;
        // almacena la clave pública, solo en cliente
        internal Buzon clave_publica;

        // seguridad de servidor asociada, solo en seguridad de servicio
        internal Seguridad seguridad_servidor;

        // almacena el billete (la serie), el índice de mensaje y el índice de bloque;
        // genera los bloque de datos (contadores) usados para encriptar;
        // el contador local de este programa se empareja con el contador remoto del programa remoto 
        // (coinciden los números)
        internal ContadorCTR contador_CTR_local;
        internal ContadorCTR contador_CTR_remoto;

        // encripta usando AES y una de las claves de encriptación; 
        // el encriptador local de este programa se empareja con el encriptador remoto del programa 
        // remoto y viceversa
        private CifradoAES  cifrado_AES_local;
        private CifradoAES  cifrado_AES_remoto;
        // autentica usando HMAC y una de las claves de autenticación; 
        // el autenticador local de este programa se empareja con el autenticador remoto del programa 
        // remoto y viceversa
        private CalculoHMAC calculo_HMAC_local;
        private CalculoHMAC calculo_HMAC_remoto;

        // se crea un preparador para los mensajes de datos y siempre está disponible;
        // los otros preparadores de mensaje se crean cuando se necesitan y luego se eliminan
        private MensajeGeneral mensaje_general;

        #endregion


        static Seguridad () {
            protocolo = new Buzon ();
            protocolo.ReservaYCopia ("com.mazc 0.2");
        }


        internal Seguridad (Conexion conexion_) {
            this.conexion = conexion_;
        }


        internal void ActivaDeServidor (byte [] clave_privada_) {
            activa      = true;
            de_servidor = true;
            //
            this.clave_privada = new Buzon ();
            this.clave_privada.ReservaYCopia (clave_privada_);
        }


        internal void ActivaDeServicio (Seguridad seguridad_servidor_) {
            activa      = true;
            de_servicio = true;
            //
            this.seguridad_servidor = seguridad_servidor_;
            //
            contador_CTR_local  = new ContadorCTR ();
            contador_CTR_remoto = new ContadorCTR ();
            contador_CTR_local .Inicia ();
            contador_CTR_remoto.Inicia ();
            //
            mensaje_general = new MensajeGeneral (this);
        }


        internal void ActivaDeCliente (byte [] clave_publica_) {
            activa     = true;
            de_cliente = true;
            //
            this.clave_publica = new Buzon ();
            this.clave_publica.ReservaYCopia (clave_publica_);
            //
            contador_CTR_local  = new ContadorCTR ();
            contador_CTR_remoto = new ContadorCTR ();
            contador_CTR_local .Inicia ();
            contador_CTR_remoto.Inicia ();
            //
            mensaje_general = new MensajeGeneral (this);
        }


        internal void Desactiva () {
            clave_privada = null;
            clave_publica = null;
            //if (protocolo.Longitud > 0) {
            //    protocolo.Libera ();
            //}
            seguridad_servidor  = null;
            contador_CTR_local  = null;
            contador_CTR_remoto = null;
            mensaje_general     = null;
            activa = false;
        }


        internal bool Activa {
            get {
                return activa;
            }
        }


        internal bool DeServidor {
            get {
                return de_servidor;
            }
        }


        internal bool DeServicio {
            get {
                return de_servicio;
            }
        }


        internal bool DeCliente {
            get {
                return de_cliente;
            }
        }


        internal Conexion Conexion {
            get {
                return conexion;
            }
        }


        internal void PreparaBuzones (int longitud) {
            mensaje_general.PreparaBuzones (longitud);
        }


        internal void Envia (int longitud) {
            Depuracion.Depura (longitud != conexion.BuzonPaquete.Longitud, "me he hecho un lío");
            //
            long billete = contador_CTR_local.NumeroSerie;
            int  indice  = contador_CTR_local.NumeroMensaje;
            //
            if (billete == 0 && indice == 0) {
                EnviaRecibePrimeros ();
            }
            //
            mensaje_general.Envia ();
            //
            contador_CTR_local.IncrementaMensaje ();
        }


        internal void Recibe () {
            long billete = contador_CTR_local.NumeroSerie;
            int  indice  = contador_CTR_local.NumeroMensaje;
            //
            if (billete == 0 && indice == 0) {
                RecibeEnviaPrimeros ();
            }
            //
            mensaje_general.Recibe ();
            //
            contador_CTR_remoto.IncrementaMensaje ();
        }


        private void EnviaRecibePrimeros () {
            Depuracion.Depura (! de_cliente, "'billete' o 'indice' fuera de lugar");
            //
            PrimerMensajeClaves mensaje_claves = new PrimerMensajeClaves (this);
            Buzon secreto = GeneraSecreto ();
            mensaje_claves.Envia (secreto);
            EstableceCripto (secreto);
            //
            MensajeSeguridad mensaje_billete = new MensajeSeguridad (this);
            long billete = mensaje_billete.Recibe ();
            //
            contador_CTR_local .CambiaSerie (billete);
            contador_CTR_remoto.CambiaSerie (billete);
        }


        private void RecibeEnviaPrimeros () {
            Depuracion.Depura (! de_servicio, "'billete' o 'indice' fuera de lugar");
            //
            PrimerMensajeClaves mensaje_claves = new PrimerMensajeClaves (this);
            Buzon secreto;
            mensaje_claves.Recibe (out secreto);
            EstableceCripto (secreto);
            //
            MensajeSeguridad mensaje_billete = new MensajeSeguridad (this);
            long billete = GeneraBillete (0);
            mensaje_billete.Envia (billete);
            //
            contador_CTR_local .CambiaSerie (billete);
            contador_CTR_remoto.CambiaSerie (billete);
        }


        private Buzon GeneraSecreto () {
            Buzon secreto = new Buzon ();
            secreto.Reserva (Seguridad.longitud_secreto);
            Aleatorio aleatorio = new Aleatorio ();
            try {
                aleatorio.Inicia ();
                aleatorio.Genera (secreto);
            } finally {
                aleatorio.Termina ();
            }
            return secreto;
        }


        private long GeneraBillete (long previo) {
            Buzon buzon = new Buzon ();
            buzon.Reserva (sizeof (long));
            Aleatorio aleatorio = new Aleatorio ();
            try {
                aleatorio.Inicia ();
                while (true) {
                    aleatorio.Genera (buzon);
                    long billete = buzon.TomaLong (0);
                    if (billete != previo) {
                        return billete;
                    }
                }
            } finally {
                aleatorio.Termina ();
            }
        }


        private void EstableceCripto (Buzon secreto) {
            Depuracion.Asevera (Seguridad.longitud_secreto == CifradoAES.BytesClave);
            Depuracion.Asevera (CifradoAES.BytesClave      == CalculoHMAC.BytesValor);
            //
            cifrado_AES_local   = new CifradoAES ();
            cifrado_AES_remoto  = new CifradoAES ();
            calculo_HMAC_local  = new CalculoHMAC ();
            calculo_HMAC_remoto = new CalculoHMAC ();
            //
            EstableceCripto (secreto, true,  true,  "clave_encripta_cliente");
            EstableceCripto (secreto, true,  false, "clave_encripta_servicio");
            EstableceCripto (secreto, false, true,  "clave_autentica_cliente");
            EstableceCripto (secreto, false, false, "clave_autentica_servicio");
        }


        private void EstableceCripto (Buzon secreto, bool encripta, bool cliente, string funcion) {
            Buzon mensaje = new Buzon ();
            mensaje.ReservaYCopia (funcion);
            Buzon clave = new Buzon ();
            clave.Reserva (Seguridad.longitud_secreto);
            //
            CalculoHMAC calculo_HMAC = new CalculoHMAC ();
            try {
                calculo_HMAC.Inicia (secreto);
                calculo_HMAC.Calcula (mensaje, clave);
            } finally {
                calculo_HMAC.Termina ();
            }
            //
            if (encripta) {
                if (cliente) {
                    if (de_cliente) {
                        cifrado_AES_local.Inicia (clave);
                    }
                    if (de_servicio) {
                        cifrado_AES_remoto.Inicia (clave);
                    }
                } else {
                    if (de_cliente) {
                        cifrado_AES_remoto.Inicia (clave);
                    }
                    if (de_servicio) {
                        cifrado_AES_local.Inicia (clave);
                    }
                }
            } else {
                if (cliente) {
                    if (de_cliente) {
                        calculo_HMAC_local.Inicia (clave);
                    }
                    if (de_servicio) {
                        calculo_HMAC_remoto.Inicia (clave);
                    }
                } else {
                    if (de_cliente) {
                        calculo_HMAC_remoto.Inicia (clave);
                    }
                    if (de_servicio) {
                        calculo_HMAC_local.Inicia (clave);
                    }
                }
            }
        }


    }


}
