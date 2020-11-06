using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    internal sealed class Seguridad {


        #region variables y constantes internas y privadas 

        // el cliente envia al servidor un valor secreto a partir del cual se crean las dos claves 
        // de encriptación y las dos de autenticación, este valor secreto es de 32 bytes
        internal const int longitud_secreto = 32;

        // el cliente envia al servidor un literal que indica el protocolo de seguridad que se está
        // usando, el servidor valida que coincidan
        static internal Buzon protocolo;

        // es la instancia que contiene a esta
        internal Conexion conexion;

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
        internal CifradoAES  cifrado_AES_local;
        internal CifradoAES  cifrado_AES_remoto;
        // autentica usando HMAC y una de las claves de autenticación; 
        // el autenticador local de este programa se empareja con el autenticador remoto del programa 
        // remoto y viceversa
        internal CalculoHMAC calculo_HMAC_local;
        internal CalculoHMAC calculo_HMAC_remoto;

        // se crea un preparador para los mensajes de datos y siempre está disponible;
        // los otros preparadores de mensaje se crean cuando se necesitan y luego se eliminan
        private MensajeGeneral mensaje_general;

        internal long     contador_bytes;
        internal DateTime contador_tiempo;

        #endregion


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


        internal void PreparaBuzones (int longitud) {
            mensaje_general.PreparaBuzones (longitud);
        }


        internal void Envia (int longitud) {
            Depuracion.Depura (de_servidor, "me he hecho un lío");
            Depuracion.Depura (longitud != conexion.BuzonPaquete.Longitud, "me he hecho un lío");
            //
            if (contador_CTR_local.NumeroSerie   == 0 && 
                contador_CTR_local.NumeroMensaje == 0   ) {
                //
                Depuracion.Depura (! de_cliente, "'billete' o 'indice' fuera de lugar");
                //
                MensajeInicio mensaje_claves = new MensajeInicio (this);
                mensaje_claves.Envia ();
                //
                MensajeSeguridad mensaje_billete = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Inicio);
                mensaje_billete.RecibeBillete ();
                //
            }
            //
            TimeSpan tiempo = DateTime.Now - contador_tiempo;
            if (contador_bytes      > 200 ||
                tiempo.TotalMinutes > 20    ) {
                contador_CTR_local .AnulaMensaje ();
                contador_CTR_remoto.AnulaMensaje ();
            }
            //
            if (contador_CTR_local.NumeroMensaje == 0) {
                //
                MensajeSeguridad mensaje_seguridad = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Secreto);
                mensaje_seguridad.EnviaSecreto ();
                //
                MensajeSeguridad mensaje_billete = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Billete);
                mensaje_billete.RecibeBillete ();
                //
            }
            //
            mensaje_general.Envia ();
        }


        internal void Recibe () {
            Depuracion.Depura (de_servidor, "me he hecho un lío");
            //
            if (contador_CTR_local.NumeroSerie   == 0 && 
                contador_CTR_local.NumeroMensaje == 0   ) {
                Depuracion.Depura (! de_servicio, "'billete' o 'indice' fuera de lugar");
                //
                MensajeInicio mensaje_claves = new MensajeInicio (this);
                mensaje_claves.Recibe ();
                //
                MensajeSeguridad mensaje_billete = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Inicio);
                mensaje_billete.EnviaBillete ();
            }
            //
            int indice;
            mensaje_general.RecibeCabecera (out indice);
            //
            if (indice == 0) {
                //
                contador_CTR_local .AnulaMensaje ();
                contador_CTR_remoto.AnulaMensaje ();
                //
                MensajeSeguridad mensaje_seguridad = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Secreto);
                mensaje_seguridad.IntegraCabecera (mensaje_general);
                mensaje_seguridad.RecibeSecreto ();
                //
                MensajeSeguridad mensaje_billete = 
                        new MensajeSeguridad (this, MensajeSeguridad.Tipologia.Billete);
                mensaje_billete.EnviaBillete ();
                //
                mensaje_general.RecibeCabecera (out indice);
                //
            }
            //
            mensaje_general.RecibeCuerpo ();
        }


        #region métodos privados


        static Seguridad () {
            protocolo = new Buzon ();
            protocolo.ReservaYCopia ("com.mazc 0.2");
        }


        internal Buzon GeneraSecreto () {
            Buzon secreto = new Buzon ();
            secreto.Reserva (Seguridad.longitud_secreto);
            DatosAleatorios aleatorio = new DatosAleatorios ();
            try {
                aleatorio.Inicia ();
                aleatorio.Genera (secreto);
            } finally {
                aleatorio.Termina ();
            }
            return secreto;
        }


        internal long GeneraBillete (long previo) {
            Buzon buzon = new Buzon ();
            buzon.Reserva (sizeof (long));
            DatosAleatorios aleatorio = new DatosAleatorios ();
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


        internal void EstableceSecreto (Buzon secreto) {
            Depuracion.Asevera (Seguridad.longitud_secreto == CifradoAES.BytesClave);
            Depuracion.Asevera (CifradoAES.BytesClave      == CalculoHMAC.BytesValor);
            //
            if (cifrado_AES_local != null) {
                cifrado_AES_local.Termina ();
            }
            cifrado_AES_local   = new CifradoAES ();
            if (cifrado_AES_remoto != null) {
                cifrado_AES_remoto.Termina ();
            }
            cifrado_AES_remoto  = new CifradoAES ();
            if (calculo_HMAC_local != null) {
                calculo_HMAC_local.Termina ();
            }
            calculo_HMAC_local  = new CalculoHMAC ();
            if (calculo_HMAC_remoto != null) {
                calculo_HMAC_remoto.Termina ();
            }
            calculo_HMAC_remoto = new CalculoHMAC ();
            //
            EstableceSecreto (secreto, true,  true,  "clave_encripta_cliente");
            EstableceSecreto (secreto, true,  false, "clave_encripta_servicio");
            EstableceSecreto (secreto, false, true,  "clave_autentica_cliente");
            EstableceSecreto (secreto, false, false, "clave_autentica_servicio");
        }


        private void EstableceSecreto (Buzon secreto, bool encripta, bool cliente, string funcion) {
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


        internal void ImprimeEnvia ( 
                Buzon billete, Buzon indice, Buzon longitud,
                string texto, params Buzon [] buzones) {
            //return;
            if (de_cliente) {
                Console.Write ("          <-----    ");
            }
            Console.Write ("{0:x} | {1:d} | {2:d} | {3:s}", 
                    billete.TomaLong (0), indice.TomaInt (0), longitud.TomaInt (0), texto);
            if (de_servicio) {
                Console.Write ("    ----->");
            }
            Console.WriteLine ();
            foreach (Buzon buzon in buzones) {
                Console.WriteLine (buzon);
            }
        }


        internal void ImprimeRecibe ( 
                Buzon billete, Buzon indice, Buzon longitud, 
                string texto, params Buzon [] buzones) {
            //return;
            if (de_cliente) {
                Console.Write ("          ----->    ");
            }
            Console.Write ("{0:x} | {1:d} | {2:d} | {3:s}", 
                    billete.TomaLong (0), indice.TomaInt (0), longitud.TomaInt (0), texto);
            if (de_servicio) {
                Console.Write ("    <-----");
            }
            Console.WriteLine ();
            foreach (Buzon buzon in buzones) {
                Console.WriteLine (buzon);
            }
        }


        #endregion


    }


}


/*

COMUNICACION
------------

Mensaje     Servidor                                   Parámetros                Cliente                                     Parámetros        Explicación   
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
tipo (A)                                               kV     -  -      <-----     0 | 0 | l | RSA ( S1 | 'mazc 1.0' )       kB     -  -       previo a la primera petición, establecimiento de clave
tipo (C)     0 | 0 | l | AES ( b1 | 'mazc 1.0' | a )   kS1"   0  0      ----->                                               kS1"   0  0       respuesta al previo, billete nuevo
tipo (B)                                               kS1'  b1  1      <-----    b1 | 1 | l | AES ( t | a )                 kS1'  b1  1       primera petición
tipo (B)    b1 | 1 | l | AES ( t | a )                 kS1"  b1  1      ----->                                               kS1"  b1  1       primera respuesta
tipo (B)                                               kS1'  b1  2      <-----    b1 | 2 | l | AES ( t | a )                 kS1'  b1  2       segunda petición
tipo (B)    b1 | 2 | l | AES ( t | a )                 kS1"  b1  2      ----->                                               kS1"  b1  2       dos respuestas sucesivas
tipo (B)    b1 | 3 | l | AES ( t | a )                 kS1"  b1  3      ----->                                               kS1"  b1  3       idem
  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  mas mensajes
tipo (B)    b1 | n | l | AES ( t | a )                 kS1"  b1  n      ----->                                               kS1"  b1  n       otra respuesta, última con esa clave
tipo (D)    b1 | 0 | l | AES ( S2 | a )                kS1"  b1  0      ----->                                               kS1"  b1  0       previo a la siguiente respuesta, cambio de clave 
tipo (E)                                               kS1'  b1  0      <-----    b1 | 0 | l | AES ( b2 | a )                kS1'  b1  0       respuesta al cambio de clave, billete nuevo
tipo (B)    b2 | 1 | l | AES ( t | a )                 kS2"  b2  1      ----->                                               kS2"  b2  1       siguiente respuesta, con clave nueva
tipo (B)                                               kS2'  b2  1      <-----    b2 | 1 | l | AES ( t | a )                 kS2'  b2  1       otra petición, sin respuesta
tipo (B)                                               kS2'  b2  2      <-----    b2 | 2 | l | AES ( t | a )                 kS2'  b2  2       otra petición
  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  mas mensajes
tipo (B)                                               kS2'  b2  n      <-----    b2 | n | l | AES ( t | a )                 kS2'  b2  n       otra petición, última con esa clave
tipo (D)                                               kS2'  b2  0      <-----    b2 | 0 | l | AES ( S3 | a )                kS2'  b2  0       previo a la siguiente petición, cambio de clave
tipo (E)    b2 | 0 | l | AES ( b3 | a )                kS2"  b2  0      ----->                                               kS2"  b2  0       respuesta al cambio de clave, billete nuevo 
tipo (B)                                               kS3'  b3  1      <-----    b3 | 1 | l | AES ( t | a )                 kS3'  b3  1       siguiente petición, con clave nueva
tipo (B)    b3 | 1 | l | AES ( t | a )                 kS3"  b3  1      ----->                                               kS3"  b3  1       respuesta 

*/



