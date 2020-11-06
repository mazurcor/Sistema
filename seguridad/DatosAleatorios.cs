//------------------------------------------------------------------------------
// archivo:     Sistema/seguridad/DatosAleatorios.cs
// versión:     28-Oct-2020, terminado, comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


    /// <summary>
    /// Genera valores aleatorios validos para su uso en criptografía.
    /// </summary>
    /// <remarks>
    /// Es una adaptación de la implementación propia de .Net, para su uso en la implementación del 
    /// canal seguro.
    /// </remarks>
    internal sealed class DatosAleatorios {


        #region variables privadas

        private RandomNumberGenerator/*RNGCryptoServiceProvider*/ algoritmo;

        #endregion


        /// <summary>
        /// Prepara la instancia para generar los datos aleatorios.
        /// </summary>
        /// <remarks>
        /// Cada llamada a 'Inicia' debe tener la correspondiente llamada a 'Termina' (en un 'try', 
        /// 'finally').
        /// </remarks>
        internal void Inicia () {
            #if DEBUG
            Depuracion.Asevera (algoritmo == null);
            #endif
            //
            algoritmo = RandomNumberGenerator.Create ();//new RNGCryptoServiceProvider ();
        }


        /// <summary>
        /// Libera los recursos usados durante la generación de datos aleatorios. Complementa la 
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
        /// Genera datos aleatorios y los escribe en el buzón.
        /// </summary>
        /// <remarks>
        /// El numero de bytes generados es igual a la longitud del buzón.
        /// </remarks>
        /// <param name="data">Buzón donde se dejarán los datos aleatorios.</param>
        internal void Genera (Buzon data) {
            #if DEBUG
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (data != null);
            Depuracion.Asevera (data.Longitud > 0);
            #endif
            //
            algoritmo.GetBytes (data.Datos);
        }


    }


}
