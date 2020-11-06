//------------------------------------------------------------------------------
// archivo:     Sistema/seguridad/CifradoAES.cs
// versión:     28-Oct-2020, terminado, comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


    /// <summary>
    /// Encripta usando el sistema simetrico AES.
    /// </summary>
    /// <remarks>
    /// Es una adaptación de la implementación propia de .Net, para su uso en la implementación del 
    /// canal seguro.
    /// El canal seguro usa el modo 'CTR'. En consecuencia, solo es necesario en cifrado de los 
    /// datos, y se hace en modo 'ECB'.
    /// </remarks>
    internal sealed class CifradoAES {
    

        /// <summary>
        /// Tamaño de clave de encriptación, en bits.
        /// </summary>
        internal const int BitsClave   = 256;
        /// <summary>
        /// Tamaño de clave de encriptación, en bytes.
        /// </summary>
        internal const int BytesClave  =  32;

        /// <summary>
        /// Tamaño de los bloques de datos a encriptar, en bits.
        /// </summary>
        internal const int BitsBloque  = 128;
        /// <summary>
        /// Tamaño de los bloques de datos a encriptar, en bytes.
        /// </summary>
        internal const int BytesBloque =  16;
    

        # region variables privadas

        // implementación de AES en .Net
        private Aes              algoritmo;
        private ICryptoTransform encriptador;

        // es un bloque vacío usado en cada encriptación
        private byte [] bloque_final;

        # endregion


        /// <summary>
        /// Prepara la instancia para realiza las encriptaciones.
        /// </summary>
        /// <remarks>
        /// Cada llamada a 'Inicia' debe tener la correspondiente llamada a 'Termina' (en un 'try', 
        /// 'finally').
        /// La clave de encriptación debe tener longitud 'BytesClave'.
        /// </remarks>
        /// <param name="clave_AES">Clave de encriptación.</param>
        internal void Inicia (Buzon clave_AES) {
            #if DEBUG
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (clave_AES != null);
            Depuracion.Asevera (clave_AES.Longitud == BytesClave);
            #endif
            //
            algoritmo = Aes.Create ();
            // el canal seguro usa el modo 'CTR', se usa AES en modo ECB y sin 'padding'
            algoritmo.Mode    = CipherMode.ECB;
            algoritmo.Padding = PaddingMode.None;
            algoritmo.Key = clave_AES.Datos;
            encriptador = algoritmo.CreateEncryptor ();
            //
            /* es innecesario:
            Depuracion.Asevera (encriptador.InputBlockSize  == BytesBloque);
            Depuracion.Asevera (encriptador.OutputBlockSize == BytesBloque);
            Depuracion.Asevera (encriptador.CanTransformMultipleBlocks);
            Depuracion.Asevera (encriptador.CanReuseTransform);
            */
            //
            bloque_final = new byte [0];
        }


        /// <summary>
        /// Libera los recursos usados durante la encriptación. Complementa la llamada a 'Inicia'.
        /// </summary>
        internal void Termina () {
            if (encriptador != null) {
                encriptador.Dispose ();
                encriptador = null;
            }
            if (algoritmo != null) {
                algoritmo.Dispose ();
                algoritmo = null;
            }
            bloque_final = null;
        }


        /// <summary>
        /// Encripta varios bloques de datos, sobrescribiendolos con en resultado.
        /// </summary>
        /// <remarks>
        /// La longitud de los datos a cifrar (y de los descifrados) no puede ser 0 y debe ser 
        /// múltiplo de 'BytesBloque'.
        /// </remarks>
        /// <param name="buzon">Uno o más bloques de datos, que se cambian por los bloques 
        /// encriptados.</param>
        internal void Cifra (Buzon buzon) {
            #if DEBUG
            Depuracion.Asevera (encriptador != null);
            Depuracion.Asevera (buzon != null);
            Depuracion.Asevera (buzon.Longitud > 0);
            Depuracion.Asevera (buzon.Longitud % BytesBloque == 0);
            #endif
            //
            // encripta todos los bloques, deja el resultado 'in situ'
            int respuesta = encriptador.TransformBlock (
                    buzon.Datos, buzon.Inicio, buzon.Longitud, buzon.Datos, buzon.Inicio);
            //
            #if DEBUG
            // en otros nodos de operación es posible que queden bloques pendientes de hacer, en 
            // este modo no es posible:
            Depuracion.Asevera (respuesta == buzon.Longitud);
            #endif
            //
            // no encripta nada, pero es necesario para hacer un 'Reset' del encriptador, véase en:
            // https://referencesource.microsoft.com/#system.core/System/Security/Cryptography/CapiSymmetricAlgorithm.cs
            encriptador.TransformFinalBlock (bloque_final, 0, 0);
        }


        #region métodos privados


        /// <summary>
        /// Validación del funcionamiento de esta clase. Solo usado en pruebas.
        /// </summary>
        private static void Valida () {
            // tomado de 
            //
            //      NIST Special Publication 800-38A
            //      Recommendation for Block Cipher Modes of Operation
            //
            //      F.1.5 ECB-AES256.Encrypt
            //
            Buzon Key = new Buzon ();
            Key.Construye (new byte [] { 
                    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4  });
            Buzon Plaintext = new Buzon ();
            Plaintext.Construye (new byte [] {          
                    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10  });
            Buzon Ciphertext = new Buzon ();
            Ciphertext.Construye (new byte [] {
                    0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,
                    0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70,
                    0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d,
                    0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7  }); 
            //
            CifradoAES aes = new CifradoAES ();
            try {
                aes.Inicia (Key);
                //
                Buzon datos = new Buzon ();
                datos.Reserva (Plaintext.Longitud);
                Buzon.CopiaDatos (Plaintext, datos);
                //
                aes.Cifra (datos);
                for (int i = 0; i < datos.Longitud; ++ i) {
                    if (datos [i] != Ciphertext [i]) {
                        throw new Exception ("Validación fallida.");
                    }
                }
                //
                // se hace dos veces para comprobar que se puede reusar
                Buzon.CopiaDatos (Plaintext, datos);
                //
                aes.Cifra (datos);
                for (int i = 0; i < datos.Longitud; ++ i) {
                    if (datos [i] != Ciphertext [i]) {
                        throw new Exception ("Validación fallida.");
                    }
                }
                //
            } finally {
                aes.Termina ();
            }
        }


        /// <summary>
        /// Investigación del funcionamiento de AES en .Net. Solo usado para pruebas.
        /// </summary>
        private class Investigacion {


            internal static void Investiga () {
                byte [] key = GenerateRandomNumber (32);
                string mensaje = 
                    "El Gobierno considera que con la aprobación de esta ley se derogó todo aquello " + 
                    "que resulte incompatible con ella, incluida la regulación establecida en el " + 
                    "artículo 73 de la Ley 16/2003 de cohesión, que solo prevé la adopción de " + 
                    "acuerdos por consenso.";
                byte [] codifica  = Encoding.UTF8.GetBytes (mensaje);
                byte [] encrypted = Encripta    (codifica, key);
                byte [] decrypted = Desencripta (encrypted, key);
                for (int i = 0; i < codifica.Length; ++i) {
                    if (codifica [i] != decrypted [i]) {
                        throw new Exception ("fallo");
                    }
                }
                Console.WriteLine ("Original Text  ==>  Decrypted Text");
                Console.WriteLine ("\"" + mensaje + "\"");
                mensaje = Encoding.UTF8.GetString (decrypted, 0, codifica.Length);
                Console.WriteLine ("\"" + mensaje + "\"");
            }


            private static byte [] GenerateRandomNumber (int length) {
                using (var randomNumberGenerator = new RNGCryptoServiceProvider()) {
                    var randomNumber = new byte[length];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }


            private static byte [] Encripta (byte [] datos, byte [] clave) {
                if (datos.Length == 0) {
                    throw new Exception ();
                }
                using (var des = new AesCryptoServiceProvider ()) {
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;
                    des.Key = clave;
                    ICryptoTransform cripto = des.CreateEncryptor ();
                    byte [] retorno = Encripta (datos, cripto);
                    return retorno;
                }
            }


            private static byte [] Encripta (byte [] datos, ICryptoTransform cripto) {
                int bloques = datos.Length / BytesBloque;
                int resto   = datos.Length - bloques * BytesBloque;
                byte [] retorno;
                if (resto == 0) {
                    retorno = new byte [bloques * BytesBloque];
                } else {
                    retorno = new byte [(bloques + 1) * BytesBloque];
                }
                Buffer.BlockCopy (datos, 0, retorno, 0, datos.Length);
                Encripta (retorno, datos.Length, cripto);
                return retorno;
            }


            private static void Encripta (byte [] datos, int longitud_datos, ICryptoTransform cripto) {
                if (datos.Length % BytesBloque != 0) {
                    throw new Exception ();
                }
                int bloques = longitud_datos / BytesBloque;
                int resto   = longitud_datos - bloques * BytesBloque;
                if (bloques > 0) {
                    int respuesta = cripto.TransformBlock (datos, 0, bloques * BytesBloque, datos, 0);
                    if (respuesta != bloques * BytesBloque) {
                        throw new Exception ();
                    }
                }
                if (resto > 0) {
                    byte [] bloque_final = new byte [BytesBloque];
                    Buffer.BlockCopy (datos, bloques * BytesBloque, bloque_final, 0, resto); 
                    bloque_final = cripto.TransformFinalBlock (bloque_final, 0, resto);
                    Buffer.BlockCopy (bloque_final, 0, datos, bloques * BytesBloque, bloque_final.Length);
                } else {
                    byte [] bloque_final = new byte [BytesBloque];
                    cripto.TransformFinalBlock (bloque_final, 0, resto);
                }
            }


            private static byte [] Desencripta (byte [] datos, byte [] clave) {
                if (datos.Length == 0) {
                    throw new Exception ();
                }
                if (datos.Length % BytesBloque != 0) {
                    throw new Exception ();
                }
                using (var des = new AesCryptoServiceProvider ()) {
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.None;
                    des.Key = clave;
                    ICryptoTransform cripto = des.CreateDecryptor ();
                    byte [] retorno = Desencripta (datos, cripto);
                    return retorno;
                }
            }


            private static byte [] Desencripta (byte [] datos, ICryptoTransform cripto) {
                // siempre es un múltiplo
                int total_bloques = datos.Length / BytesBloque; 
                int respuesta = cripto.TransformBlock (datos, 0, datos.Length, datos, 0);
                if (respuesta != datos.Length) {
                    throw new Exception ();
                }
                cripto.TransformFinalBlock (datos, 0, 0);
                return datos;
            }


        }


        #endregion


    }


}
