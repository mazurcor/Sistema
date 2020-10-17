using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    class ModoSeguridad {
    }


    class Seguridad {


        internal void ActivaDeServidor (byte [] clave_privada) {
        
        }


        internal void ActivaDeServicio (Seguridad seguridad_servidor) {
        
        }


        internal void ActivaDeCliente (byte [] clave_publica) {
        
        }


        internal bool DeServidor {
            get {
                return true;
            }
        }


        internal bool DeCliente {
            get {
                return true;
            }
        }

        internal void PreparaBuzones (int longitud) {
            throw new NotImplementedException ();
        }

        internal void Recibe () {
            throw new NotImplementedException ();
        }

        internal void Envia () {
            throw new NotImplementedException ();
        }
    }


}
