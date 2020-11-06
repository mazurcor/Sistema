using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    // Clase base de preparación de los mensajes encriptados con AES.
    internal class MensajeSimetrico : MensajeBase {


        #region variables protegidas

        //  Mensaje a enviar.
        //      buzón 'mensaje':
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
        //  Auxiliares.
        //      buzon 'verifica':
        //          +---+
        //          |   |
        //          +---+
        //      buzon 'contador':
        //          +---+
        //          |   |
        //          +---+

        protected const int bytes_autentica = CalculoHMAC.BytesValor;
        protected       int bytes_sensible;
        protected       int bytes_cifrado;

        protected Buzon buzon_autentica;
        protected Buzon buzon_sensible;
        protected Buzon buzon_cifrado;

        private Buzon buzon_verifica;
        private Buzon buzon_contador;

        #endregion


        internal MensajeSimetrico (Seguridad seguridad_) : 
                base (seguridad_) {
            buzon_autentica = new Buzon ();
            buzon_sensible  = new Buzon ();
            buzon_cifrado   = new Buzon ();
            buzon_verifica  = new Buzon ();
            buzon_contador  = new Buzon ();
            //
            PreparaPrivados ();
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
            seguridad.calculo_HMAC_local.Calcula (buzon_sensible, buzon_autentica);
            Cifra_AES (seguridad.cifrado_AES_local, seguridad.contador_CTR_local);
        }


        internal void DescifraVerifica () {
            Cifra_AES (seguridad.cifrado_AES_remoto, seguridad.contador_CTR_remoto);
            // AQUI: comprobar la autenticacion
            seguridad.calculo_HMAC_remoto.Calcula (buzon_sensible, buzon_verifica);
            if (Buzon.DatosIguales (buzon_verifica, buzon_autentica)) {
                // AQUI: ¿que hacer????
                return;
            }
        }


        #region métodos privados 


        private void PreparaPrivados () {
            buzon_verifica.Reserva (bytes_autentica);
            buzon_contador.Reserva (ContadorCTR.BytesContador);
        }


        private void Cifra_AES (CifradoAES cifra_AES, ContadorCTR cuenta_CTR) {
            int posicion = 0;
            int longitud = buzon_cifrado.Longitud;
            ////
            while (true) {
                cuenta_CTR.AsignaContador (buzon_contador);
                cifra_AES.Cifra (buzon_contador);
                //
                int resto;
                if (CifradoAES.BytesBloque <= longitud) {
                    resto = CifradoAES.BytesBloque;
                } else {
                    resto = longitud;
                }
                //
                for (int i = 0; i < resto; ++ i) {
                    buzon_cifrado [posicion] ^= buzon_contador [i];
                    posicion ++;
                    longitud --;
                }
                //
                if (longitud <= 0) {
                    return;
                }
                //
                cuenta_CTR.IncrementaBloque ();
            }
        }


        #endregion


    }


}
