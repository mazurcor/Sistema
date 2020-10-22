using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    internal class Seguridad {


        #region constantes

        private const string literal_protocolo = "com.mazc 0.2";

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
        private Buzon clave_privada;
        // almacena la clave pública, solo en cliente
        private Buzon clave_publica;

        //
        private Buzon protocolo;

        // seguridad de servidor asociada, solo en seguridad de servicio
        private Seguridad seguridad_servidor;


        private ContadorCTR contador_CTR_local;
        private ContadorCTR contador_CTR_remoto;

        #endregion


        internal Seguridad (Conexion conexion_) {
            this.conexion = conexion_;
        }


        internal void ActivaDeServidor (byte [] clave_privada_) {
            activa      = true;
            de_servidor = true;
            //
            this.clave_privada.ReservaCopia (clave_privada_);
            protocolo.ReservaCopia (literal_protocolo);
        }


        internal void ActivaDeServicio (Seguridad seguridad_servidor_) {
            activa      = true;
            de_servicio = true;
            //
            this.seguridad_servidor = seguridad_servidor_;
            //
            contador_CTR_local  = new ContadorCTR ();
            contador_CTR_remoto = new ContadorCTR ();
        }


        internal void ActivaDeCliente (byte [] clave_publica_) {
            activa     = true;
            de_cliente = true;
            //
            this.clave_publica.ReservaCopia (clave_publica_);
            protocolo.ReservaCopia (literal_protocolo);
            //
            contador_CTR_local  = new ContadorCTR ();
            contador_CTR_remoto = new ContadorCTR ();
        }


        internal void Desactiva () {
            if (clave_privada.Longitud > 0) {
                clave_privada.Libera ();
            }
            if (clave_publica.Longitud > 0) {
                clave_publica.Libera ();
            }
            if (protocolo.Longitud > 0) {
                protocolo.Libera ();
            }
            seguridad_servidor = null;
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
            throw new NotImplementedException ();
        }


        internal void Envia () {
            throw new NotImplementedException ();
        }


        internal void Recibe () {
            throw new NotImplementedException ();
        }


    }


}
