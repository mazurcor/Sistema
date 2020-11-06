// no sé como hacer esto
// más adelante lo pensaré


using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
//using System.Runtime.CompilerServices;


namespace com.mazc.Sistema {


    class Depuracion {


        internal static void Depura (bool condicion, string mensaje) {
            if (condicion) {
                throw new Exception (mensaje);
            }
            // AQUI:
        }


        internal static void Asevera (bool condicion) {
            if (! condicion) {
                throw new Exception ();
            }
            // AQUI:
        }


        internal static void Cancela (Exception excepcion) {
            throw excepcion;
        }


    }


}
