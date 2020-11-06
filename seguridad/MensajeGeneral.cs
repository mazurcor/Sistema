using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


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


        internal void Envia () {
            buzon_billete .PonLong (0, seguridad.contador_CTR_local.NumeroSerie);  
            buzon_indice  .PonInt  (0, seguridad.contador_CTR_local.NumeroMensaje);
            buzon_longitud.PonInt  (0, bytes_mensaje);
            //
            base.AutenticaCifra ();
            //
            conexion.EnviaSocket (conexion.BuzonMensaje, bytes_mensaje);
            //
            seguridad.ImprimeEnvia (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "AES ( M | hmac )");
            //
            seguridad.contador_bytes += conexion.BuzonPaquete.Longitud;
            seguridad.contador_CTR_local.IncrementaMensaje ();
       }


        internal void RecibeCabecera (out int indice_) {
            conexion.RecibeSocket (conexion.BuzonMensaje, 0, bytes_cabecera);
            indice_ = buzon_indice.TomaInt (0);
        }


        internal void RecibeCuerpo () {
            // se valida el mensaje
            if (buzon_billete.TomaLong (0) != seguridad.contador_CTR_remoto.NumeroSerie   ||
                buzon_indice .TomaInt  (0) != seguridad.contador_CTR_remoto.NumeroMensaje   ) {
                // ¿que hacer????
                return;
            }
            // validar resto:
            int bytes_resto   = buzon_longitud.TomaInt (0) - bytes_cabecera;
            int bytes_paquete = bytes_resto - bytes_autentica;
            //
            PreparaBuzones (bytes_paquete);
            //
            conexion.RecibeSocket (conexion.BuzonMensaje, bytes_cabecera, bytes_resto);
            //
            seguridad.ImprimeRecibe (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "AES ( M | hmac )");
            //
            base.DescifraVerifica ();    
            //
            seguridad.contador_bytes += conexion.BuzonPaquete.Longitud;
            seguridad.contador_CTR_remoto.IncrementaMensaje ();
        }


        #region métodos privados


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


        #endregion

    }


}
