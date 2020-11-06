using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


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

        private bool de_inicio;
        private bool con_secreto;
        private bool con_billete;

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


        internal enum Tipologia {
            Inicio,
            Secreto,
            Billete
        }


        internal MensajeSeguridad (Seguridad seguridad_, Tipologia tipologia) :
                base (seguridad_) {
            Prepara (tipologia);
        }


        internal void EnviaSecreto () {
            buzon_billete .PonLong (0, seguridad.contador_CTR_local.NumeroSerie);
            buzon_indice  .PonInt  (0, seguridad.contador_CTR_local.NumeroMensaje);
            buzon_longitud.PonInt  (0, buzon_mensaje.Longitud);
            //
            Buzon secreto = seguridad.GeneraSecreto ();
            Buzon.CopiaDatos (secreto, this.buzon_clave);
            //
            AutenticaCifra ();
            //
            conexion.EnviaSocket (buzon_mensaje, buzon_mensaje.Longitud);
            //
            seguridad.ImprimeEnvia (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "AES ( S2 | hmac )");
            //
            seguridad.EstableceSecreto (secreto);
        }


        internal void IntegraCabecera (MensajeGeneral mensaje_general) {
            Buzon.CopiaDatos (mensaje_general.BuzonBillete,  buzon_billete);
            Buzon.CopiaDatos (mensaje_general.BuzonIndice,   buzon_indice);
            Buzon.CopiaDatos (mensaje_general.BuzonLongitud, buzon_longitud);
            
        }


        internal void RecibeSecreto () {
            conexion.RecibeSocket (
                    buzon_mensaje, bytes_cabecera, buzon_mensaje.Longitud - bytes_cabecera);
            //
            seguridad.ImprimeRecibe (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "AES ( S2 | hmac )");
            //             
            // se valida el mensaje
            if (buzon_billete .TomaLong (0) == 0 ||
                buzon_indice  .TomaInt  (0) != 0 ||
                buzon_longitud.TomaInt  (0) != buzon_mensaje.Longitud) {
                // ????
                return;
            }
            //
            DescifraVerifica ();
            //
            seguridad.EstableceSecreto (this.buzon_clave);
        }


        internal void EnviaBillete () {
            buzon_billete .PonLong (0, seguridad.contador_CTR_local.NumeroSerie);
            buzon_indice  .PonInt  (0, seguridad.contador_CTR_local.NumeroMensaje);
            buzon_longitud.PonInt  (0, buzon_mensaje.Longitud);
            //
            long billete = seguridad.GeneraBillete (0);
            this.buzon_numero.PonLong (0, billete);
            if (bytes_protocolo > 0) {
                Buzon.CopiaDatos (Seguridad.protocolo, buzon_protocolo);
            }
            //
            AutenticaCifra ();
            //
            conexion.EnviaSocket (buzon_mensaje, buzon_mensaje.Longitud);
            //
            if (bytes_protocolo > 0) {
                seguridad.ImprimeEnvia (
                        buzon_billete, buzon_indice, buzon_longitud, 
                        "AES ( b1 | 'com.mazc 0.2' | hmac )");
            } else {
                seguridad.ImprimeEnvia (
                        buzon_billete, buzon_indice, buzon_longitud, 
                        "AES ( b2 | hmac )");
            }
            //
            seguridad.contador_CTR_local .CambiaSerie (billete);
            seguridad.contador_CTR_remoto.CambiaSerie (billete);
            seguridad.contador_tiempo = DateTime.Now;
        }


        internal void RecibeBillete () {
            conexion.RecibeSocket (buzon_mensaje, 0, buzon_mensaje.Longitud);
            //
            if (bytes_protocolo > 0) {
                seguridad.ImprimeRecibe (
                        buzon_billete, buzon_indice, buzon_longitud, 
                        "AES ( b1 | 'com.mazc 0.2' | hmac )");
            } else {
                seguridad.ImprimeRecibe (
                        buzon_billete, buzon_indice, buzon_longitud, 
                        "AES ( b2 | hmac )");
            }
            //
            // se valida el mensaje
            if (//buzon_billete .TomaLong (0) == 0 ||
                buzon_indice  .TomaInt  (0) != 0 ||
                buzon_longitud.TomaInt  (0) != buzon_mensaje.Longitud) {
                // ????
                return;
            }
            //
            DescifraVerifica ();
            //
            if (bytes_protocolo > 0) {
                if (! Buzon.DatosIguales (buzon_protocolo, Seguridad.protocolo)) {
                    // ????
                    return;
                }
            }
            //
            long billete = buzon_numero.TomaLong (0);
            //
            seguridad.contador_CTR_local .CambiaSerie (billete);
            seguridad.contador_CTR_remoto.CambiaSerie (billete);
            seguridad.contador_tiempo = DateTime.Now;
        }


        #region métodos privados


        private void Prepara (Tipologia tipologia) {
            bytes_clave     = 0;
            bytes_numero    = 0;
            bytes_protocolo = 0;
            if (tipologia == Tipologia.Secreto) {
                bytes_clave = Seguridad.longitud_secreto;
            }
            if (tipologia == Tipologia.Inicio || tipologia == Tipologia.Billete) {
                bytes_numero = bytes_billete;
            }
            if (tipologia == Tipologia.Inicio) {
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
            if (bytes_clave != 0) {
                buzon_mensaje.ConstruyePorcion (inicio_clave, bytes_clave, buzon_clave);
            }
            if (bytes_numero != 0) {
                buzon_mensaje.ConstruyePorcion (inicio_numero, bytes_numero, buzon_numero);
            }
            if (bytes_protocolo != 0) {
                buzon_mensaje.ConstruyePorcion (inicio_protocolo, bytes_protocolo, buzon_protocolo);
            }
            PreparaGrupos (buzon_mensaje, bytes_datos);
        }


        #endregion


    }


}
