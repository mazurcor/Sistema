using System;
using System.Collections.Generic;
using System.Text;


namespace com.mazc.Sistema {


    // Clase que prepara el primer mensajes de establecimiento de secreto. Encriptado con RSA.
    internal sealed class MensajeInicio : MensajeBase {


        #region variables privadas

        //  Mensaje a encriptar. 
        //      buzón 'texto':
        //          +---+---+
        //          | s | p |
        //          +---+---+
        //      porciones de 'texto':
        //          s: secreto
        //          p: protocolo (dos bytes por caracter)
        //
        //  Mensaje a enviar. 
        //      buzón 'mensaje':
        //          +---+---+---+-------+
        //          | b | i | l |   c   |
        //          +---+---+---+-------+
        //      porciones de 'mensaje':
        //          b: billete
        //          i: indice
        //          l: longitud
        //          c: cifrado (de texto)

        private const int bytes_secreto   = Seguridad.longitud_secreto;
        private       int bytes_protocolo;
        private       int bytes_texto;

        private Buzon buzon_texto;
        private Buzon buzon_secreto;
        private Buzon buzon_protocolo;

        private const int bytes_cifrado = CifradoRSA.BytesEncriptado;
        private const int bytes_mensaje = bytes_cabecera + bytes_cifrado;
            
        private Buzon buzon_mensaje;
        private Buzon buzon_cifrado;

        #endregion


        internal MensajeInicio (Seguridad seguridad_) : 
                base (seguridad_) {
            Depuracion.Asevera (! seguridad_.DeServidor);
            //
            Prepara ();
        }


        // envia el mensaje (desde el servicio)
        internal void Envia () {
            buzon_billete .PonLong (0, 0);
            buzon_indice  .PonInt  (0, 0);
            buzon_longitud.PonInt  (0, buzon_mensaje.Longitud);
            //
            Buzon secreto = seguridad.GeneraSecreto ();
            //
            Buzon.CopiaDatos (secreto, this.buzon_secreto);
            Buzon.CopiaDatos (Seguridad.protocolo, this.buzon_protocolo);
            //
            CifradoRSA cifrado_RSA = new CifradoRSA ();
            try {
                cifrado_RSA.IniciaPublica (seguridad.clave_publica);
                cifrado_RSA.CifraPublica (buzon_texto, buzon_cifrado);
            } finally { 
                cifrado_RSA.Termina ();
            } 
            //
            conexion.EnviaSocket (buzon_mensaje, buzon_mensaje.Longitud);
            //
            seguridad.ImprimeEnvia (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "RSA ( S1 | protocolo )"                    );
            //
            seguridad.EstableceSecreto (secreto);
        }


        // recibe el mensaje (en el cliente)
        internal void Recibe () {
            conexion.RecibeSocket (buzon_mensaje, 0, buzon_mensaje.Longitud);
            //
            seguridad.ImprimeRecibe (
                    buzon_billete, buzon_indice, buzon_longitud, 
                    "RSA ( S1 | protocolo )"                    );
            //
            // se valida el mensaje
            if (buzon_billete .TomaInt (0) != 0 ||
                buzon_indice  .TomaInt (0) != 0 ||
                buzon_longitud.TomaInt (0) != buzon_mensaje.Longitud) {
                throw new ErrorConexion ("Violación del protocolo de seguridad.");
            }
            //
            CifradoRSA cifrado_RSA = new CifradoRSA ();
            try {
                cifrado_RSA.IniciaPrivada (seguridad.seguridad_servidor.clave_privada);
                cifrado_RSA.DescifraPrivada (buzon_cifrado, buzon_texto);
            } finally { 
                cifrado_RSA.Termina ();
            }
            //
            if (! Buzon.DatosIguales (this.buzon_protocolo, Seguridad.protocolo)) {
                throw new ErrorConexion ("Protocolo de seguridad inconsistente.");
            }
            //
            seguridad.EstableceSecreto (this.buzon_secreto);
        }


        #region métodos privados


        // prepara los buzones
        private void Prepara () {
            bytes_protocolo  = Seguridad.protocolo.Longitud;
            bytes_texto      = bytes_secreto + bytes_protocolo;
            //
            buzon_texto     = new Buzon ();
            buzon_secreto   = new Buzon ();
            buzon_protocolo = new Buzon ();
            //
            buzon_texto.Reserva (bytes_texto);
            buzon_texto.ConstruyePorcion (            0, bytes_secreto,   buzon_secreto);
            buzon_texto.ConstruyePorcion (bytes_secreto, bytes_protocolo, buzon_protocolo);
            //
            buzon_mensaje = new Buzon ();
            buzon_cifrado = new Buzon ();
            //
            buzon_mensaje.Reserva (bytes_mensaje);
            PreparaCabecera (buzon_mensaje);
            buzon_mensaje.ConstruyePorcion (bytes_cabecera,  bytes_cifrado,  buzon_cifrado);
        }


        #endregion


    }


}
