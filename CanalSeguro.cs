using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {



    // Clase que prepara el primer mensajes de establecimiento de secreto. Encriptado con RSA.
    internal sealed class PrimerMensajeClaves {


        #region variables privadas

        // instancias que están usando este mensaje;
        private Seguridad seguridad;
        private Conexion  conexion;

        //  Mensaje a encriptar. 
        //  buzón 'texto':
        //      +---+---+
        //      | s | p |
        //      +---+---+
        //  fragmentos de 'texto':
        //      s: secreto
        //      p: protocolo (dos bytes por caracter)
        //
        //  Mensaje a enviar. 
        //  buzón 'mensaje':
        //      +---+---+---+---+
        //      | b | i | l | c |
        //      +---+---+---+---+
        //  fragmentos de mensaje:
        //      b: billete
        //      i: indice
        //      l: longitud
        //      c: cifrado (de texto)

        private Buzon texto;
        private Buzon secreto;
        private Buzon protocolo;

        private Buzon mensaje;
        private Buzon billete;
        private Buzon indice;
        private Buzon longitud;
        private Buzon cifrado;

        #endregion


        internal PrimerMensajeClaves (Seguridad seguridad_) {
            Plantea ();
        }


        private void Plantea () {
            int bytes_secreto    = Seguridad.bytes_secreto;
            int bytes_protocolo  = Seguridad.literal_protocolo.Length * 2;
            int bytes_texto      = bytes_secreto + bytes_protocolo;
            int inicio_secreto   = 0;
            int inicio_protocolo = inicio_secreto + bytes_secreto;
            //
            this.texto = new Buzon ();
            this.texto.Reserva (bytes_texto);
            this.secreto   = new Buzon ();
            this.protocolo = new Buzon ();
            this.texto.CreaFragmento (inicio_secreto,   bytes_secreto,   this.secreto);
            this.texto.CreaFragmento (inicio_protocolo, bytes_protocolo, this.protocolo);
            //
            int bytes_billete   = sizeof (long);
            int bytes_indice    = sizeof (int);
            int bytes_longitud  = sizeof (int);
            int bytes_cifrado   = CifradoRSA.MaximoBytesMensaje;
            int bytes_mensaje   = bytes_billete + bytes_indice + bytes_longitud + bytes_cifrado;
            int inicio_billete  = 0;
            int inicio_indice   = inicio_billete  + bytes_billete;
            int inicio_longitud = inicio_indice   + bytes_indice;
            int inicio_cifrado  = inicio_longitud + bytes_longitud;

            this.mensaje = new Buzon ();
            this.mensaje.Reserva (bytes_mensaje);
            this.billete  = new Buzon ();
            this.indice   = new Buzon ();
            this.longitud = new Buzon ();
            this.cifrado  = new Buzon ();
            this.mensaje.CreaFragmento (inicio_billete,  bytes_billete,  this.billete);
            this.mensaje.CreaFragmento (inicio_indice,   bytes_indice,   this.indice);
            this.mensaje.CreaFragmento (inicio_longitud, bytes_longitud, this.longitud);
            this.mensaje.CreaFragmento (inicio_cifrado,  bytes_cifrado,  this.cifrado);
        }


        internal void Envia (Buzon secreto_) {
//            Buzon.CopiaDatos (secreto_, this.secreto, Seguridad.bytes_secreto);
//            this.protocolo.PonString (0, Seguridad.literal_protocolo);
//            this.billete  .PonInt (0, 0);
//            this.indice   .PonInt (0, 0);
//            this.longitud .PonInt (0, mensaje.Longitud);
//            //
//            CifradoRSA cifrado_RSA = new CifradoRSA ();
//            cifrado_RSA.IniciaPublica (seguridad.clave_publica);
//            cifrado_RSA.CifraPublica (texto, cifrado);
//            cifrado_RSA.Termina ();
//            //
//            conexion.EnviaSocket (mensaje, mensaje.Longitud);
//            //
////            seguridad.ImprimeEnvia (billete, indice, longitud, "RSA ( S1 | protocolo )");
        }


        internal Buzon Recibe () {
            Buzon secreto = new Buzon ();
            secreto.Reserva (Seguridad.bytes_secreto);
            


//            conexion.RecibeSocket (mensaje, 0, mensaje.Longitud);
//            //
////            seguridad.ImprimeRecibe (billete, indice, longitud, "RSA ( S1 | protocolo )");
//            //
//            // se valida el mensaje
//            if (billete .TomaInt (0) != 0 ||
//                indice  .TomaInt (0) != 0 ||
//                longitud.TomaInt (0) != mensaje.Longitud) {
//                // ????
//                return;
//            }
//            //
//            CifradoRSA cifrado_RSA = new CifradoRSA ();
//            cifrado_RSA.IniciaPrivada (seguridad.seguridad_servidor.clave_privada);
//            cifrado_RSA.DescifraPrivada (cifrado.Almacen, texto.Almacen);
//            cifrado_RSA.Termina ();
//            //
//            if (! Buzon.Iguales (protocolo, seguridad.protocolo)) {
//                // ????
//                return;
//            }
//            Buzon::Copia (secreto, secreto_);




            return secreto;
        }


    }


    // Clase base de preparación de los mensajes encriptados con AES.
    internal class MensajeBase {


        #region variables protegidas

        // instancias que están usando este mensaje;
        protected Seguridad seguridad;
        protected Conexion  conexion;

        #endregion


        internal MensajeBase (Seguridad seguridad_) {
            this.seguridad = seguridad_;
            this.conexion  = seguridad_.Conexion;
        }


    }


    // Clase que prepara el primer mensajes de establecimiento de billete. Derivada de 
    // 'MensajaeBase' por ser encriptados con AES.
    internal sealed class PrimerMensajeBillete : 
            MensajeBase {


        internal PrimerMensajeBillete (Seguridad seguridad_) :
                base (seguridad_) {
        }


        internal long Recibe () {
            throw new NotImplementedException ();
        }


        internal void Envia (long billete) {
            throw new NotImplementedException ();
        }


    }


    // Clase que prepara los mensajes generales de envío y recepción de datos. Derivada de 
    // 'MensajaeBase' por ser encriptados con AES.
    internal sealed class MensajeGeneral : 
            MensajeBase {


        #region variables privadas



        #endregion


        internal MensajeGeneral (Seguridad seguridad_) :
                base (seguridad_) {
        }

        internal void Envia () {
            throw new NotImplementedException ();
        }

        internal void Recibe () {
            throw new NotImplementedException ();
        }

        internal void PreparaBuzones (int longitud) {
            throw new NotImplementedException ();
        }
    }


    internal sealed class Seguridad {


        #region constantes privadas

        // el cliente envia al servidor un valor secreto a partir del cual se crean las dos claves 
        // de encriptación y las dos de autenticación, este valor secreto es de 64 bytes ¿por qué?
        internal const int bytes_secreto = 64;

        // el cliente envia al servidor un literal que indica el protocolo de seguridad que se está
        // usando, el servidor valida que coincidan
        internal const string literal_protocolo = "com.mazc 0.2";

        #endregion


        #region variables privadas 

        // es la instancia que contiene a esta
        private Conexion conexion;

        // indica que se ha activado esta seguridad
        private bool activa;
        // indica con que papel se ha activado esta seguridad
        private bool de_servidor; 
		private bool de_servicio;
		private bool de_cliente;

        // almacena la clave privada, solo en servidor
        Buzon clave_privada;
        // almacena la clave pública, solo en cliente
        Buzon clave_publica;

        // seguridad de servidor asociada, solo en seguridad de servicio
        internal Seguridad seguridad_servidor;

        // almacena el billete (la serie), el índice de mensaje y el índice de bloque;
        // genera los bloque de datos (contadores) usados para encriptar;
        // el contador local de este programa se empareja con el contador remoto del programa remoto 
        // (coinciden los números)
        private ContadorCTR contador_CTR_local;
        private ContadorCTR contador_CTR_remoto;

        // encripta usando AES y una de las claves de encriptación; 
        // el encriptador local de este programa se empareja con el encriptador remoto del programa remoto
        private CifradoAES  cifrado_AES_local;
        private CifradoAES  cifrado_AES_remoto;
        // autentica usando HMAC y una de las claves de autenticación; 
        // el autenticador local de este programa se empareja con el autenticador remoto del programa remoto
        private CalculoHMAC calculo_HMAC_local;
        private CalculoHMAC calculo_HMAC_remoto;

        // hay un preparador para los mensajes de datos siempre disponible;
        // los otros preparadores de mensaje se crean cuando se necesitan y luego se eliminan
        private MensajeGeneral mensaje_general;

        #endregion


        internal Seguridad (Conexion conexion_) {
            this.conexion = conexion_;
        }


        internal void ActivaDeServidor (byte [] clave_privada_) {
            activa      = true;
            de_servidor = true;
            //
            this.clave_privada = new Buzon ();
            this.clave_privada.ReservaCopia (clave_privada_);
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
            this.clave_publica.ReservaCopia (clave_publica_);
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
            PrimerMensajeBillete mensaje_billete = new PrimerMensajeBillete (this);
            long billete = mensaje_billete.Recibe ();
            //
            contador_CTR_local .CambiaSerie (billete);
            contador_CTR_remoto.CambiaSerie (billete);
        }


        private void RecibeEnviaPrimeros () {
            Depuracion.Depura (! de_servicio, "'billete' o 'indice' fuera de lugar");
            //
            PrimerMensajeClaves mensaje_claves = new PrimerMensajeClaves (this);
            Buzon secreto = mensaje_claves.Recibe ();
            EstableceCripto (secreto);
            //
            PrimerMensajeBillete mensaje_billete = new PrimerMensajeBillete (this);
            long billete = GeneraBillete (0);
            mensaje_billete.Envia (billete);
            //
            contador_CTR_local .CambiaSerie (billete);
            contador_CTR_remoto.CambiaSerie (billete);
        }


        private Buzon GeneraSecreto () {
            Buzon secreto = new Buzon ();
            secreto.Reserva (bytes_secreto);
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
            Depuracion.Asevera (CifradoAES.BytesClave == CalculoHMAC.BytesValor);
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
            Buzon salt = new Buzon ();
            salt.ReservaCopia (funcion);
            Buzon clave = new Buzon ();
            clave.Reserva (CifradoAES.BytesClave);
            //
            CalculoHMAC calculo_HMAC = new CalculoHMAC ();
            try {
                calculo_HMAC.Inicia (salt);
                calculo_HMAC.Calcula (secreto, clave);
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
