using System;
using System.Collections.Generic;
using System.Text;
//using System.Runtime.CompilerServices;


namespace com.mazc.Sistema {


    class Depuracion {


        internal static void Valida (bool condicion, string mensaje) {
            if (condicion) {
                throw new Exception (mensaje);
            }
            // AQUI:
        }


        //internal static void Valida (bool condicion) {
        //    if (condicion) {
        //        throw new Exception ("Fallo de validación");
        //    }
        //    // AQUI:
        //}


        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
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
