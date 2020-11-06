using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    // Clase base de las clases que preparan los mensajes
    internal class MensajeBase {


        #region variables protegidas

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
            this.conexion  = seguridad_.conexion;
            //
            buzon_billete  = new Buzon ();
            buzon_indice   = new Buzon ();
            buzon_longitud = new Buzon ();
        }


        protected void PreparaCabecera (Buzon buzon_mensaje) {
            int inicio_billete  = 0;
            int inicio_indice   = bytes_billete;
            int inicio_longitud = bytes_billete + bytes_indice;
            //
            buzon_mensaje.ConstruyePorcion (inicio_billete,  bytes_billete,  buzon_billete);
            buzon_mensaje.ConstruyePorcion (inicio_indice,   bytes_indice,   buzon_indice);
            buzon_mensaje.ConstruyePorcion (inicio_longitud, bytes_longitud, buzon_longitud);
        }


        internal Buzon BuzonBillete {
            get {
                return buzon_billete;
            }
        }


        internal Buzon BuzonIndice {
            get {
                return buzon_indice;
            }
        }


        internal Buzon BuzonLongitud {
            get {
                return buzon_longitud;
            }
        }


    }


}
