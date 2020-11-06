//------------------------------------------------------------------------------
// archivo:     Sistema/seguridad/CalculoHMAC.cs
// versión:     28-Oct-2020, terminado, comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


    /// <summary>
    /// Calcula codigos de autenticación de mensaje basados en hash (HMAC). Para el cáculo de los 
    /// hash usa SHA-256.
    /// </summary>
    /// <remarks>
    /// Se calcula el valor HMAC sobre un mensaje de longitud arbitraria y produce un código HMAC de 
    /// 256 bits. El cálculo incluye el uso de una clave de autenticación secreta. 
    /// </remarks>
    internal sealed class CalculoHMAC {
  

        /// <summary>
        /// Longitud en bis de los códigos HMAC calculados.
        /// </summary>
        internal const int BitsValor  = 256;
        /// <summary>
        /// Longitud en bytes de los códigos HMAC calculados.
        /// </summary>
        internal const int BytesValor =  32;

        /// <summary>
        /// Longitud en bytes de la clave de autenticación usada en el cálculo de los códigos HMAC.
        /// </summary>
        //internal const int BytesClave = 64;


        #region variables privadas

        private HMACSHA256 algoritmo;

        #endregion


        /// <summary>
        /// Prepara la instancia para realizar los cálculos, estableciendo la clave de 
        /// autenticación.
        /// </summary>
        /// <remarks>
        /// 'clave_SHA' puede ser de cualquier tamaño, pero el recomendado es 64 bytes. 
        /// Cada llamada a 'Inicia' debe tener la correspondiente llamada a 'Termina' (en un 'try', 
        /// 'finally').
        /// </remarks>
        /// <param name="clave_SHA">Clave de autenticación, de longitud 'BytesClave'.</param>
        internal void Inicia (Buzon clave_SHA) {
            #if DEBUG
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (clave_SHA != null);
            Depuracion.Asevera (clave_SHA.Longitud > 0);
            #endif
            //
            byte [] entrada;
            if (clave_SHA.Inicio == 0 && clave_SHA.Datos.Length == clave_SHA.Longitud) {
                entrada = clave_SHA.Datos;
            } else {
                entrada = new byte [clave_SHA.Longitud];
                clave_SHA.TomaBinario (0, entrada);
            }
            //           
            algoritmo = new HMACSHA256 (entrada);
            //
            #if DEBUG
            Depuracion.Asevera (algoritmo.CanReuseTransform );
            Depuracion.Asevera (algoritmo.CanTransformMultipleBlocks); 	
            Depuracion.Asevera (algoritmo.HashSize == BitsValor);
            #endif            
        }


        /// <summary>
        /// Libera los recursos usados durante calculos de códigos HMAC. Complementa la 
        /// llamada a 'Inicia'.
        /// </summary>
        internal void Termina () {
            if (algoritmo == null) {
                return;
            }
            //
            algoritmo.Dispose ();
        }


        /// <summary>
        /// Calcula el código HMAC del mensaje y lo deja en el buzón indicado.
        /// </summary>
        /// <remarks>
        /// El buzón 'valor_HMAC' puede ser vacío; en ese caso se crea un array de bytes de longitud 
        /// 'BytesValor' y se encapsula en el buzón. Si 'valor_HMAC' no es vacío, su longitud debe 
        /// ser 'BytesValor'.
        /// </remarks>
        /// <param name="mensaje">Mensaje para el que se calcula el código HMAC.</param>
        /// <param name="valor_HMAC">Código HMAC calculado, de longitud BytesValor.</param>
        internal void Calcula (Buzon mensaje, Buzon valor_HMAC) {
            #if DEBUG
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (mensaje != null);
            Depuracion.Asevera (mensaje.Longitud > 0);
            Depuracion.Asevera (valor_HMAC != null);
            if (valor_HMAC.Longitud > 0) {
                Depuracion.Asevera (valor_HMAC.Longitud == BytesValor);
            }
            #endif
            //
            byte [] retorno = algoritmo.ComputeHash (mensaje.Datos, mensaje.Inicio, mensaje.Longitud);
            //
            #if DEBUG
            Depuracion.Asevera (retorno.Length == BytesValor);
            #endif
            //
            if (valor_HMAC.Longitud == 0) {
                valor_HMAC.Construye (retorno);
            } else {
                Buffer.BlockCopy (retorno, 0, valor_HMAC.Datos, valor_HMAC.Inicio, BytesValor);
            }
        }


    }


}
