//------------------------------------------------------------------------------
// archivo:     Sistema/Conexion.cs
// versión:     18-Oct-2020
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


    public class Aleatorio {


        #region variables privadas

        private RNGCryptoServiceProvider algoritmo;

        #endregion


        public void Inicia () {
            Depuracion.Asevera (algoritmo == null);
            //
            algoritmo = new RNGCryptoServiceProvider ();
        }


        public void Termina () {
            if (algoritmo == null) {
                return;
            }
            //
            algoritmo.Dispose ();
        }


        public void Genera (byte [] data) {
            Depuracion.Asevera (algoritmo != null);
            //
            algoritmo.GetBytes (data);
        }


    }




    public class CalculoHMAC {
  
        
        /// longitud del valor de resumen (hash) de los datos 
        public const int BitsValor  = 256;
        public const int BytesValor =  32;


        #region variables privadas

        private HMACSHA256 algoritmo;

        #endregion


        // El tamaño recomendado de 'clave_SHA' es 64 bytes. Si es mayor, el algoritmo hace un hash 
        // (usando SHA-256) y si es menor, lo completa a 64 bytes.
        public void Inicia (byte [] clave_SHA) {
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (clave_SHA != null);
            Depuracion.Asevera (clave_SHA.Length > 0);
            //
            algoritmo = new HMACSHA256 (clave_SHA);
            //
            Depuracion.Asevera (algoritmo.CanReuseTransform );
            Depuracion.Asevera (algoritmo.CanTransformMultipleBlocks); 	
            Depuracion.Asevera (algoritmo.HashSize == BitsValor);
        }


        public void Termina () {
            if (algoritmo == null) {
                return;
            }
            //
            algoritmo.Dispose ();
        }


        public void Calcula (byte [] mensaje, byte [] valor_HMAC) {
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (valor_HMAC.Length == 32);
            //
            byte [] retorno = algoritmo.ComputeHash (mensaje);
            //
            Depuracion.Asevera (retorno.Length == 32);
            //
            Buffer.BlockCopy (retorno, 0, valor_HMAC, 0, valor_HMAC.Length);
        }


    }


    /// <summary>
    /// Encripta usando el sistema simetrico AES.
    /// </summary>
    /// <remarks>
    /// Es una adaptación de la implementación propia de .Net, para su uso en la implementación del 
    /// canal seguro.
    /// El canal seguro usa el modo 'CTR'. En consecuencia, solo es necesario en cifrado de los 
    /// datos, y se hace en modo 'ECB'.
    /// </remarks>
    public class CifradoAES {
    

        /// <summary>
        /// Tamaño de clave de encriptación, en bits.
        /// </summary>
        public const int BitsClave   = 256;
        /// <summary>
        /// Tamaño de clave de encriptación, en bytes.
        /// </summary>
        public const int BytesClave  =  32;

        /// <summary>
        /// Tamaño de los bloques de datos a encriptar, en bits.
        /// </summary>
        public const int BitsBloque  = 128;
        /// <summary>
        /// Tamaño de los bloques de datos a encriptar, en bytes.
        /// </summary>
        public const int BytesBloque =  16;
    

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
        /// </remarks>
        /// <param name="clave_AES">Clave de encriptación, de longitud 'BytesClave'.</param>
        void Inicia (byte [] clave_AES) {
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (clave_AES != null);
            Depuracion.Asevera (clave_AES.Length == BytesClave);
            //
            algoritmo = Aes.Create ();
            // el canal seguro usa el modo 'CTR', se usa AES en modo ECB y sin 'padding'
            algoritmo.Mode    = CipherMode.ECB;
            algoritmo.Padding = PaddingMode.None;
            algoritmo.Key     = clave_AES;
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
        void Termina () {
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
        /// <param name="buzon">uno o más bloques de datos, que se cambian por los bloques 
        /// encriptados; la longitud debe ser múltiplo de 'BytesBloque'</param>
        void Cifra (byte [] buzon) {
            Depuracion.Asevera (encriptador != null);
            Depuracion.Asevera (buzon != null);
            Depuracion.Asevera (buzon.Length > 0);
            Depuracion.Asevera (buzon.Length % BytesBloque == 0);
            //
            // encripta todos los bloques, deja el resultado 'in situ'
            int respuesta = encriptador.TransformBlock (buzon, 0, buzon.Length, buzon, 0);
            // en otros nodos de operación es posible que queden bloques pendientes de hacer, en 
            // este modo no es posible:
            Depuracion.Asevera (respuesta == buzon.Length);
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
            byte [] Key = { 
                    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4  };
            byte [] Plaintext = {          
                    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10  };
            byte [] Ciphertext = {
                    0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,
                    0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70,
                    0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d,
                    0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7  }; 
            //
            CifradoAES aes = new CifradoAES ();
            try {
                aes.Inicia (Key);
                //
                byte [] datos = new byte [Plaintext.Length];
                //
                Buffer.BlockCopy (Plaintext, 0, datos, 0, Plaintext.Length);
                aes.Cifra (datos);
                for (int i = 0; i < datos.Length; ++ i) {
                    if (datos [i] != Ciphertext [i]) {
                        throw new Exception ("Validación fallida.");
                    }
                }
                //
                // se hace dos veces para comprobar que se puede reusar
                Buffer.BlockCopy (Plaintext, 0, datos, 0, Plaintext.Length);
                aes.Cifra (datos);
                for (int i = 0; i < datos.Length; ++ i) {
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


            public static void Investiga () {
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


    /// <summary>
    /// Implementa el sistema de contadores usado en la encriptación simétrica en modo CTR.
    /// </summary>
    /// <remarks>
    /// Participa en la implementación del canal seguro, el cual usa el modo 'CTR'. Esta clase 
    /// genera los bloques de datos, llamados contadores, que se encriptan en el modo CTR.
    /// Un contador se forma a partir de:
    ///     * Una marca binaria para la serie de mensajes. Los mensajes de la serie son los que se 
    ///       encriptan con la misma clave de encriptación.
    ///     * Un número de mensaje dentro de la serie. El número de mensaje recorre los valores: 
    ///       1, ···, MaximoNumero, 0 . Tras MaximoNumero el contador pasa a cero.
    ///     * Un número de bloque dentro del mensaje. El número de bloque recorre los valores: 
    ///       0, ···, MaximoNumero.     
    /// </remarks>
    public class ContadorCTR {


        /// <summary>
        /// Tamaño de un contador, en bytes.
        /// </summary>
        public const int BytesContador = CifradoAES.BytesBloque;

        /// <summary>
        /// Valor máximo de los números de mensaje.
        /// </summary>
        public const int MaximoMensaje = 9;//int.MaxValue;

        /// <summary>
        /// Valor máximo de los números de bloque.
        /// </summary>
        public const int MaximoBloque = 9;//int.MaxValue;


        #region varibles privadas

        // indica si alguna vez se ha llamado a 'IniciaSerie'
        private bool serie_iniciada;
        // indica si el bloque contador preparado se ha leido (con 'AsignaContador')
        private bool contador_leido;

        // valores contenidos en el contador
        private long numero_serie;
        private int  numero_mensaje;
        private int  numero_bloque;

        // almacena el contador preparado
        private byte [] buzon_contador;

        // distribución de campos en el contador
        private const int bytes_bloque   = 4;
        private const int bytes_serie    = 8;
        private const int bytes_mensaje  = 4;
        private const int inicio_bloque  = 0;
        private const int inicio_serie   = inicio_bloque + bytes_bloque;
        private const int inicio_mensaje = inicio_serie  + bytes_serie;

        #endregion


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <remarks>
        /// El número de mensaje y el número bloque serán cero.
        /// El contador no puede ser leido.
        /// </remarks>
        public ContadorCTR () {
            buzon_contador = new byte [BytesContador];
        }


        #region métodos privados


        // Indica si la marca de serie es nueva, comparandola con la anterior.
        private bool SerieNueva (long serie) {
            if (! serie_iniciada) {
                return true;
            }
            return numero_serie != serie;
        }


        // Pone en el buzon del contador la marca de serie actual.
        private void PonSerieBuzon () {
            buzon_contador [inicio_serie    ] = (byte) (numero_serie >> 56);
            buzon_contador [inicio_serie + 1] = (byte) (numero_serie >> 48);
            buzon_contador [inicio_serie + 2] = (byte) (numero_serie >> 40);
            buzon_contador [inicio_serie + 3] = (byte) (numero_serie >> 32);
            buzon_contador [inicio_serie + 4] = (byte) (numero_serie >> 24);
            buzon_contador [inicio_serie + 5] = (byte) (numero_serie >> 16);
            buzon_contador [inicio_serie + 6] = (byte) (numero_serie >>  8);
            buzon_contador [inicio_serie + 7] = (byte) (numero_serie      );
        }


        // Pone en el buzón del contador el número indicado en la posición indicada.
        private void PonNumeroBuzon (int numero, int inicio) {
            buzon_contador [inicio    ] = (byte) (numero >> 24);
            buzon_contador [inicio + 1] = (byte) (numero >> 16);
            buzon_contador [inicio + 2] = (byte) (numero >>  8);
            buzon_contador [inicio + 3] = (byte) (numero      );
        }


        #endregion


        /// <summary>
        /// Establece una nueva serie para ser usada en los contadores. La serie se asocia a una 
        /// clave de encriptación nueva.
        /// </summary>
        /// <remarks>
        /// Los contadores de la serie usarán la marca de serie indicada. El primer contador de 
        /// La serie usará el número de mensaje 1 y el número de bloque 0.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        /// <param name="serie">marca de la nueva serie, </param>
        public void IniciaSerie (long serie, int mensaje) {
            Depuracion.Asevera (! serie_iniciada || contador_leido);
            // valida que la marca de serie previa es distinta de la indicada
            Depuracion.Asevera (SerieNueva (serie));
            //
            numero_serie   = serie;
            numero_mensaje = mensaje;
            numero_bloque  = 0;
            //
            PonSerieBuzon  ();
            PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            serie_iniciada = true;
            contador_leido = false;
        }


        /// <summary>
        /// Incrementa el número de mensaje usado en los contadores. Se incremente cuando hay un 
        /// mensaje nuevo.
        /// </summary>
        /// <remarks>
        /// El número de bloque pasa a cero.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        public void IncrementaMensaje () {
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (numero_mensaje > 0);
            //
            if (numero_mensaje < MaximoMensaje) {
                numero_mensaje ++;
            } else {
                numero_mensaje = 0;
            }
            numero_bloque = 0;
            //
            PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            contador_leido = false;
        }


        /// <summary>
        /// Incrementa el número de bloque usado en los contadores. Cada bloque de un mensaje debe 
        /// ser distinto.
        /// </summary>
        /// <remarks>
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        public void IncrementaBloque () {
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (0 <= numero_bloque && numero_bloque < MaximoBloque);
            //
            numero_bloque ++;
            //
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            contador_leido = false;
        }


        /// <summary>
        /// Número del mensaje del contador. Recorre los valores:  1, ···, MaximoNumero, 0 
        /// </summary>
        public int NumeroMensaje {
            get {
                return numero_mensaje;
            }
        }


        /// <summary>
        /// Número de bloque del contador. Recorre los valores:  0, ···, MaximoNumero
        /// </summary>
        public int NumeroBloque {
            get {
                return numero_bloque;
            }
        }


        /// <summary>
        /// Número de serie del contador. Es el asignado en 'IniciaSerie'.
        /// </summary>
        public long NumeroSerie {
            get {
                return numero_serie;
            }
        }


        /// <summary>
        /// Copia el contador en el lugar indicado.
        /// </summary>
        /// <remarks>
        /// El contador debe estar preprado para ser leido. Esto se hace con 'IniciaSerie', 
        /// 'IncrementaMensaje' o 'IncrementaBloque'. Tras copiarlo (con este método) el contador 
        /// deja de estar preparado para ser leido.
        /// </remarks>
        /// <param name="destino">array de bytes donde se copiará en contador</param>
        /// <param name="posicion">en destino donde comenzará la copia del contador</param>
        public void AsignaContador (byte [] destino, int posicion) {
            Depuracion.Asevera (destino != null);
            Depuracion.Asevera (posicion + BytesContador <= destino.Length);
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (! contador_leido);
            //
            Buffer.BlockCopy (buzon_contador, 0, destino, posicion, BytesContador);
            contador_leido = true;
        }


        #region métodos privados


        private static void Valida () {
            ContadorCTR CTR = new ContadorCTR ();
            long serie1 = 0x0F1F2F3F4F5F6F7F;
            long serie2 = 0x7E8E9EAEBECEDEEE;
            //
            CTR.IniciaSerie (serie1, 0);
            Imprime (CTR);
            for (int i = 1; i < 10; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }

            CTR.IniciaSerie (serie2, 0);
            Imprime (CTR);
            for (int i = 1; i < 10; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }

            CTR.IncrementaBloque ();
            Imprime (CTR);

            CTR.IncrementaBloque ();
            Imprime (CTR);

            CTR.IncrementaBloque ();
            Imprime (CTR);

            CTR.IncrementaMensaje ();
            Imprime (CTR);

            CTR.IncrementaBloque ();
            Imprime (CTR);

            CTR.IncrementaBloque ();
            Imprime (CTR);

            CTR.IncrementaBloque ();
            Imprime (CTR);

        }


        private static void Imprime (ContadorCTR CTR) {
            byte [] contador = new byte [ContadorCTR.BytesContador];
            CTR.AsignaContador (contador, 0);
            for (int i = 0; i < ContadorCTR.BytesContador; ++ i) {
                Console.Write ("{0:X2}", contador [i]);
            }
            Console.WriteLine ();
        }


        #endregion


    }


    /// <summary>
    /// Encripta usando el sistema asimetrico RSA.
    /// </summary>
    /// <remarks>
    /// Es una adaptación de la implementación propia de .Net, para su uso en la implementación del 
    /// canal seguro.
    /// </remarks>
    public class CifradoRSA {


        /// <summary>
        /// Tamaño de clave de encriptación, en bits.
        /// </summary>
        const int BitsClave = 2048;


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
        /// <param name="clave_publica">clave pública</param>
        /// <param name="clave_privada">clave privada</param>
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
        /// Cada llamada a 'Inicia' debe tener la correspondiente llamada a 'Termina' (en un 'try', 
        /// 'finally').
        /// </remarks>
        /// <param name="clave_AES">Clave de encriptación, de longitud 'BytesClave'.</param>
        public void IniciaPublica (byte [] clave) {
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (! publica && ! privada);
            //
            algoritmo = RSA.Create (BitsClave);
            int i;
            algoritmo.ImportRSAPublicKey (clave, out i);
            //
            privada = false;
            publica = true;
        }


        /// <summary>
        /// Prepara la instancia para realiza encriptaciones usando la clave privada indicada.
        /// </summary>
        /// <remarks>
        /// Cada llamada a 'Inicia' debe tener la correspondiente llamada a 'Termina' (en un 'try', 
        /// 'finally').
        /// </remarks>
        /// <param name="clave_AES">Clave de encriptación, de longitud 'BytesClave'.</param>
        public void IniciaPrivada (byte [] clave_privada) {
            Depuracion.Asevera (algoritmo == null);
            Depuracion.Asevera (! publica && ! privada);
            //
            algoritmo = RSA.Create (BitsClave);
            int i;
            algoritmo.ImportRSAPrivateKey (clave_privada, out i);
            //
            privada = true;
            publica = false;
        }


        /// <summary>
        /// Libera los recursos usados durante la encriptación. Complementa la llamada a 'Inicia'.
        /// </summary>
        public void Termina () {
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (publica || privada);
            //
            algoritmo.Dispose ();
            algoritmo = null;
            privada = false;
            publica = false;
        }


        /// <summary>
        /// Encripta con la clave pública el mensaje indicado y devuelve el resultado.
        /// </summary>
        /// <remarks>
        /// Se debe establecer previamente la clave pública medianta 'IniciaPublica'.
        /// </remarks>
        /// <param name="mensaje">mensaje a encriptar</param>
        /// <param name="cifrado">resultado de la enriptación</param>
        public void CifraPublica (byte [] mensaje, out byte [] cifrado) {
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (publica);
            //
            cifrado = algoritmo.Encrypt (mensaje, RSAEncryptionPadding.OaepSHA512);
        }


        /// <summary>
        /// Desencripta 'cifrado' con la clave privada y devuelve el mensaje.
        /// </summary>
        /// <param name="cifrado">mensaje cifrado</param>
        /// <param name="mensaje">mensaje descifrado</param>
        public void DescifraPrivada (byte [] cifrado, out byte [] mensaje) {
            Depuracion.Asevera (algoritmo != null);
            Depuracion.Asevera (privada);
            //
            mensaje = algoritmo.Decrypt (cifrado, RSAEncryptionPadding.OaepSHA512);
        }


        #region métodos privados


        /// <summary>
        /// Validación del funcionamiento de esta clase. Solo usado en pruebas.
        /// </summary>
        private static void Valida () {
            byte [] clave_publica;
            byte [] clave_privada;
            CifradoRSA.GeneraParClaves (out clave_publica, out clave_privada);
            //ImprimeCarga ("clave_publica", clave_publica);
            //ImprimeCarga ("clave_privada", clave_privada);
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
            byte [] codificado = Encoding.UTF8.GetBytes (original);
            Console.WriteLine ("codificado = {0} bytes", codificado.Length);
            CifradoRSA rsa = new CifradoRSA ();
            byte [] encriptado;
            try {
                rsa.IniciaPublica (clave_publica);
                rsa.CifraPublica (codificado, out encriptado);
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
                byte [] desencriptado;
                rsa.DescifraPrivada (encriptado, out desencriptado);
                descodificado = Encoding.Default.GetString (desencriptado);
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
