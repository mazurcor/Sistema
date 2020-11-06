//------------------------------------------------------------------------------
// archivo:     Sistema/seguridad/CifradoRSA.cs
// versión:     28-Oct-2020, terminado, comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


    /// <summary>
    /// Encripta usando el sistema asimetrico RSA.
    /// </summary>
    /// <remarks>
    /// Es una adaptación de la implementación propia de .Net, para su uso en la implementación del 
    /// canal seguro.
    /// </remarks>
    public sealed class CifradoRSA {


        /// <summary>
        /// Tamaño de clave de encriptación, en bits.
        /// </summary>
        internal const int BitsClave = 2048;

        /// <summary>
        /// Tamaño máximo en bytes del mensaje a encriptar.
        /// </summary>
        internal const int MaximoBytesMensaje = 126;

        /// <summary>
        /// Tamaño del mensaje encriptado.
        /// </summary>
        internal const int BytesEncriptado = 256;


        # region variables privadas

        // implementación de RSA en .Net
        private RSA algoritmo;

        // la instancia se puede usar en dos modos:
        private bool publica;
        private bool privada;

        #endregion


        /// <summary>
        /// Genera un par de claves de encriptación asimetrica y las devuelve.
        /// </summary>
        /// <remarks>
        /// El formato de exportación es PKCS#1.
        /// </remarks>
        /// <param name="clave_publica">Clave pública de cifrado.</param>
        /// <param name="clave_privada">Clave privada de descifrado.</param>
        internal static void GeneraParClaves (Buzon clave_publica, Buzon clave_privada) {
            #if DEBUG
            Depuracion.Asevera (clave_publica != null);
            Depuracion.Asevera (clave_publica.Longitud == 0);
            Depuracion.Asevera (clave_privada != null);
            Depuracion.Asevera (clave_privada.Longitud == 0);
            #endif
            //
            RSA algoritmo = RSA.Create (BitsClave);
            try {
                byte [] publica; 
                byte [] privada;
                GeneraParClaves (out publica, out privada);
                clave_publica.Construye (publica);
                clave_privada.Construye (privada);
            } finally {
                algoritmo.Dispose ();
            }
        }


        /// <summary>
        /// Genera un par de claves de encriptación asimetrica y las devuelve.
        /// </summary>
        /// <remarks>
        /// El formato de exportación es PKCS#1.
        /// </remarks>
        /// <param name="clave_publica">Clave pública de cifrado.</param>
        /// <param name="clave_privada">Clave privada de descifrado.</param>
        public static void GeneraParClaves (out byte [] clave_publica, out byte [] clave_privada) {
            RSA algoritmo = RSA.Create (BitsClave);
            try {
                clave_publica = algoritmo.ExportRSAPublicKey ();
                clave_privada = algoritmo.ExportRSAPrivateKey ();
            } finally {
                algoritmo.Dispose ();
            }
        }


        /// <summary>
        /// Prepara la instancia para realiza desencriptaciones usando la clave pública indicada.
        /// </summary>
        /// <remarks>
        /// Cada llamada a 'IniciaPublica' debe tener la correspondiente llamada a 'Termina' (en un 
        /// 'try', 'finally').
        /// El formato de la clave es: "ASN.1-BER-encoded PKCS#1 RSAPublicKey structure".
        /// </remarks>
        /// <param name="clave_publica">Clave publica de encriptación.'.</param>
        internal void IniciaPublica (Buzon clave_publica) {
            #if DEBUG
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (! publica && ! privada);
            Depuracion.Asevera (clave_publica != null);
            Depuracion.Asevera (! clave_publica.EsPorcion);
            Depuracion.Asevera (clave_publica.Longitud > 0);
            #endif
            //
            algoritmo = RSA.Create (BitsClave);
            int i;
            algoritmo.ImportRSAPublicKey (clave_publica.Datos, out i);
            //
            privada = false;
            publica = true;
        }


        /// <summary>
        /// Prepara la instancia para realiza encriptaciones usando la clave privada indicada.
        /// </summary>
        /// <remarks>
        /// Cada llamada a 'IniciaPrivada' debe tener la correspondiente llamada a 'Termina' (en un 
        /// 'try', 'finally').
        /// El formato de la clave es: "ASN.1-BER-encoded PKCS#1 RSAPrivateKey structure".
        /// </remarks>
        /// <param name="clave_AES">Clave privada de encriptación.</param>
        internal void IniciaPrivada (Buzon clave_privada) {
            #if DEBUG
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (! publica && ! privada);
            Depuracion.Asevera (clave_privada != null);
            Depuracion.Asevera (! clave_privada.EsPorcion);
            Depuracion.Asevera (clave_privada.Longitud > 0);
            #endif
            //
            algoritmo = RSA.Create (BitsClave);
            int i;
            algoritmo.ImportRSAPrivateKey (clave_privada.Datos, out i);
            //
            privada = true;
            publica = false;
        }


        /// <summary>
        /// Libera los recursos usados durante la encriptación. Complementa la llamada a 'Inicia'.
        /// </summary>
        internal void Termina () {
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (publica || privada);
            //
            algoritmo.Dispose ();
            algoritmo = null;
            privada = false;
            publica = false;
        }


        /// <summary>
        /// Encripta con la clave pública un mensaje y devuelve el resultado cifrado.
        /// </summary>
        /// <remarks>
        /// Se debe establecer previamente la clave pública medianta 'IniciaPublica'.
        /// El tamaño máximo del mensaje a encriptar es 'MaximoBytesMensaje'.
        /// El buzón 'cifrado' puede ser vacío; en ese caso se crea un array de bytes de longitud 
        /// 'BytesEncriptado' y se encapsula en el buzón. Si 'cifrado' no es vacío, su longitud debe 
        /// ser 'BytesEncriptado'.
        /// </remarks>
        /// <param name="mensaje">Mensaje a cifrar.</param>
        /// <param name="cifrado">Buzon donde se copiará el mensaje cifrado, puede ser vacío o no.</param>
        internal void CifraPublica (Buzon mensaje, Buzon cifrado) {
            #if DEBUG
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (publica);
            Depuracion.Asevera (mensaje != null);
            Depuracion.Asevera (mensaje.Longitud > 0);
            Depuracion.Asevera (mensaje.Longitud <= MaximoBytesMensaje);
            Depuracion.Asevera (cifrado != null);
            if (cifrado.Longitud > 0) {
                Depuracion.Asevera (cifrado.Longitud == BytesEncriptado);
            }
            #endif
            //
            byte [] datos = algoritmo.Encrypt (mensaje.Datos, RSAEncryptionPadding.OaepSHA512);
            //
            #if DEBUG
            Depuracion.Asevera (datos.Length == BytesEncriptado);
            #endif
            //
            if (cifrado.Longitud == 0) {
                cifrado.Construye (datos);
            } else {
                Buffer.BlockCopy (datos, 0, cifrado.Datos, cifrado.Inicio, BytesEncriptado);
            }
        }


        /// <summary>
        /// Desencripta un valor con la clave privada y devuelve el mensaje descifrado.
        /// </summary>
        /// <remarks>
        /// Se debe establecer previamente la clave privada medianta 'IniciaPrivada'.
        /// El tamaño de 'cifrado' debe ser 'BytesEncriptado'.
        /// El támaño de 'mensaje' es el del mensaje original. No puede ser mayor que 
        /// 'MaximoBytesMensaje'.
        /// El buzón 'mensaje' puede ser vacío; en ese caso se crea un array de bytes y se encapsula 
        /// en el buzón. Si 'cifrado' no es vacío, su longitud debe ser suficiente para almacenar el
        /// mensaje descifrado.
        /// </remarks>
        /// <param name="cifrado">Mensaje cifrado.</param>
        /// <param name="mensaje">Buzon donde se copiará el mensaje descifrado, puede ser vacío o no.</param>
        internal void DescifraPrivada (Buzon cifrado, Buzon mensaje) {
            #if DEBUG
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (privada);
            Depuracion.Asevera (cifrado != null);
            Depuracion.Asevera (cifrado.Longitud == BytesEncriptado);
            Depuracion.Asevera (mensaje != null);
            #endif
            //
            byte [] entrada;
            if (cifrado.Inicio == 0 && cifrado.Datos.Length == cifrado.Longitud) {
                entrada = cifrado.Datos;
            } else {
                entrada = new byte [cifrado.Longitud];
                cifrado.TomaBinario (0, entrada);
            }
            //
            byte [] salida = algoritmo.Decrypt (entrada, RSAEncryptionPadding.OaepSHA512);
            //
            #if DEBUG
            if (mensaje.Longitud > 0) {
                Depuracion.Asevera (salida.Length <= mensaje.Longitud);
            }
            #endif
            //
            if (mensaje.Longitud == 0) {
                mensaje.Construye (salida);
            } else {
                mensaje.PonBinario (0, salida);
                //Buffer.BlockCopy (salida, 0, mensaje.Datos, mensaje.Inicio, salida.Length);
            }
        }


        #region métodos privados


        /// <summary>
        /// Validación del funcionamiento de esta clase. Solo usado en pruebas.
        /// </summary>
        private static void Valida () {
            Buzon clave_publica = new Buzon ();
            Buzon clave_privada = new Buzon ();
            CifradoRSA.GeneraParClaves (clave_publica, clave_privada);
            //
            string texto = 
                    "Ahora mismo, nuestra predicción dice que Joe Biden es el candidato con más " + 
                    "posibilidades de ser el próximo presidente, con 4 de 5 opciones, aunque Donald  " + 
                    "Trump ganaría 1 de 5 veces.";
            //
            // el límite de los datos a cifrar es 126 bytes (véase RFC-8017)
            // para conseguir ese límite, texto debe ser de 123 caracteres
            // al poner 124 caracteres, los datos a cifrar pasan a 127 y se produce una excepción
            string original = texto.Substring (0, 123);
            
            //
            Buzon codificado = new Buzon ();  
            codificado.Construye (Encoding.UTF8.GetBytes (original));
            Console.WriteLine ("codificado = {0} bytes", codificado.Longitud);
            CifradoRSA rsa = new CifradoRSA ();
            Buzon encriptado = new Buzon ();
            //encriptado.Reserva (256);
            try {
                rsa.IniciaPublica (clave_publica);
                rsa.CifraPublica (codificado, encriptado);
            } catch (Exception e) {
                Console.WriteLine ("EXCEPCIÓN:");
                Console.WriteLine ("    " + e.Message); 
                return;
            } finally {
                rsa.Termina ();
            }
            //
            string descodificado;
            try {
                rsa.IniciaPrivada (clave_privada);
                Buzon desencriptado = new Buzon ();
                //desencriptado.Reserva (encriptado.Longitud);
                rsa.DescifraPrivada (encriptado, desencriptado);
                descodificado = Encoding.Default.GetString (desencriptado.Datos);
            } finally {
                rsa.Termina ();
            }
            //
            for (int i = 0 ; i < original.Length; ++ i) {
                if (original [i] != descodificado [i]) {
                    Console.WriteLine ("No coincide: ");
                    Console.WriteLine(descodificado);
                    return;
                }
            }
            Console.WriteLine("CORRECTO");
        }


        #endregion


    }


}
