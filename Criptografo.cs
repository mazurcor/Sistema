//------------------------------------------------------------------------------
// archivo:     Sistema/Criptografo.cs
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
    internal sealed class Aleatorio {


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
            algoritmo = new HMACSHA256 (clave_SHA.Datos);
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
            byte [] retorno = algoritmo.ComputeHash (mensaje.Datos);
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


    /// <summary>
    /// Implementa el sistema de contadores usado en la encriptación simétrica en modo CTR.
    /// </summary>
    /// <remarks>
    /// Participa en la implementación del canal seguro, el cual usa el modo 'CTR'. Esta clase 
    /// genera los bloques de datos, llamados contadores, que se encriptan en el modo CTR.
    /// Un contador se forma a partir de:
    ///     * Una número para la serie de mensajes. Los mensajes de la serie se encriptan con la 
    ///       misma clave de encriptación. Es un número aleatorio de 64 bits.
    ///     * Un número de mensaje dentro de la serie. El número de mensaje recorre los valores: 
    ///       1, ···, MaximoNumero, 0 . Tras MaximoNumero el contador pasa a cero.
    ///     * Un número de bloque dentro del mensaje. El número de bloque recorre los valores: 
    ///       0, ···, MaximoNumero.     
    /// </remarks>
    internal sealed class ContadorCTR {


        /// <summary>
        /// Tamaño de un contador, en bytes.
        /// </summary>
        internal const int BytesContador = CifradoAES.BytesBloque;

        /// <summary>
        /// Valor máximo de los números de mensaje.
        /// </summary>
        internal const int MaximoMensaje = int.MaxValue;

        /// <summary>
        /// Valor máximo de los números de bloque.
        /// </summary>
        internal const int MaximoBloque = int.MaxValue;


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
        private const int inicio_serie   = 0;
        private const int inicio_mensaje = inicio_serie   + bytes_serie;
        private const int inicio_bloque  = inicio_mensaje + bytes_mensaje;
 
        #endregion


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <remarks>
        /// Es necesario iniciar la serie con 'IniciaSerie'.
        /// </remarks>
        internal ContadorCTR () {
            serie_iniciada = false;
            buzon_contador = new byte [BytesContador];
        }


        /// <summary>
        /// Establece los primeros números a ser usados en los contadores.
        /// </summary>
        /// <remarks>
        /// Establece el número de serie 0, el número de mensaje 0 y el número de bloque 0. Se usa
        /// solo la primera vez que se cambia la serie, para las siguientes se usa 'CambiaSerie'.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        /// <param name="serie">marca de la nueva serie, </param>
        internal void Inicia () {
            Depuracion.Asevera (! serie_iniciada);
            //
            numero_serie   = 0;
            numero_mensaje = 0;
            numero_bloque  = 0;
            //
            PonNumeroBuzon (numero_serie,   inicio_serie);
            PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            serie_iniciada = true;
            contador_leido = false;
        }


        /// <summary>
        /// Establece una nueva serie para ser usada en los contadores. La serie se asocia a una 
        /// clave de encriptación nueva.
        /// </summary>
        /// <remarks>
        /// Los contadores de la serie usarán el número de serie indicado. El primer contador de 
        /// la serie usará el número de mensaje 1 y el número de bloque 0. 
        /// Solo se puede usar este método cuando el número de mensaje es 0.
        /// El número de serie indicado no puede ser 0 y debe ser distinto al de la serie anterior.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        /// <param name="serie">marca de la nueva serie, </param>
        internal void CambiaSerie (long serie) {
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (numero_mensaje == 0);
            Depuracion.Asevera (serie != 0);
            Depuracion.Asevera (numero_serie != serie);
            //
            numero_serie   = serie;
            numero_mensaje = 1;
            numero_bloque  = 0;
            //
            PonNumeroBuzon (numero_serie,   inicio_serie);
            PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            serie_iniciada = true;
            contador_leido = false;
        }


        /// <summary>
        /// Pone a cero el número de mensaje usado en los contadores. Se pone a cero para cambiar la
        /// clave de encriptación y la serie.
        /// </summary>
        /// <remarks>
        /// El número de serie y el número de bloque pasan a ser 0.
        /// Solo se puede usar este método cuando el número de serie y el número de mensaje no es 0.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        internal void AnulaMensaje () {
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (numero_serie != 0);
            Depuracion.Asevera (numero_mensaje > 0);
            //
            numero_mensaje = 0;
            numero_bloque  = 0;
            //
            PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            PonNumeroBuzon (numero_bloque,  inicio_bloque);
            //
            contador_leido = false;
        }


        /// <summary>
        /// Incrementa el número de mensaje usado en los contadores. Se incrementa cuando hay un 
        /// mensaje nuevo.
        /// </summary>
        /// <remarks>
        /// El número de bloque pasa a 0.
        /// Solo se puede usar este método cuando el número de serie y el número de mensaje no es 0.
        /// El contador queda preparado para ser leido (con 'AsignaContador').
        /// </remarks>
        internal void IncrementaMensaje () {
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (numero_serie != 0);
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
        internal void IncrementaBloque () {
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
        /// Número de serie del contador. Es el asignado en 'IniciaSerie'.
        /// </summary>
        internal long NumeroSerie {
            get {
                return numero_serie;
            }
        }


        /// <summary>
        /// Número del mensaje del contador. Recorre los valores:  1, ···, MaximoNumero, 0 
        /// </summary>
        internal int NumeroMensaje {
            get {
                return numero_mensaje;
            }
        }


        /// <summary>
        /// Número de bloque del contador. Recorre los valores:  0, ···, MaximoNumero
        /// </summary>
        internal int NumeroBloque {
            get {
                return numero_bloque;
            }
        }


        /// <summary>
        /// Copia el contador en el lugar indicado.
        /// </summary>
        /// <remarks>
        /// El contador debe estar preprado para ser leido. Esto se hace con 'IniciaSerie', 
        /// 'IncrementaMensaje' o 'IncrementaBloque'. Tras copiarlo (con este método) el contador 
        /// deja de estar preparado para ser leido.
        /// El buzón donde se copia el contador debe ser de longitud 'BytesContador'.
        /// </remarks>
        /// <param name="destino">Buzón donde se copiará en contador.</param>
        internal void AsignaContador (Buzon destino) {
            Depuracion.Asevera (destino != null);
            Depuracion.Asevera (destino.Longitud == BytesContador);
            Depuracion.Asevera (serie_iniciada);
            Depuracion.Asevera (! contador_leido);
            //
            Buffer.BlockCopy (buzon_contador, 0, destino.Datos, destino.Inicio, BytesContador);
            contador_leido = true;
        }


        #region métodos privados


        // Pone en el buzon del contador la marca de serie actual.
        private void PonNumeroBuzon (long numero, int inicio) {
            buzon_contador [inicio    ] = (byte) (numero_serie >> 56);
            buzon_contador [inicio + 1] = (byte) (numero_serie >> 48);
            buzon_contador [inicio + 2] = (byte) (numero_serie >> 40);
            buzon_contador [inicio + 3] = (byte) (numero_serie >> 32);
            buzon_contador [inicio + 4] = (byte) (numero_serie >> 24);
            buzon_contador [inicio + 5] = (byte) (numero_serie >> 16);
            buzon_contador [inicio + 6] = (byte) (numero_serie >>  8);
            buzon_contador [inicio + 7] = (byte) (numero_serie      );
        }


        // Pone en el buzón del contador el número indicado en la posición indicada.
        private void PonNumeroBuzon (int numero, int inicio) {
            buzon_contador [inicio    ] = (byte) (numero >> 24);
            buzon_contador [inicio + 1] = (byte) (numero >> 16);
            buzon_contador [inicio + 2] = (byte) (numero >>  8);
            buzon_contador [inicio + 3] = (byte) (numero      );
        }


        #endregion


        #region métodos privados


        // para que funcione esta prueba hay que poner:
        //      internal const int MaximoMensaje = 5;//int.MaxValue;


        /*

        las llamadas a los métodos solo pueden producirse en cierto orden:

            método                  serie     mensaje     bloques
            --------------------------------------------------------------
            IniciaSerie:                      
                                    0         0           0, 1, 2, ···
            CambiaSerie:                                           
                                    b1        1           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b1        2           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b1        3           0, 1, 2, ···

                · · · · · · · · · ·                                
        
            IncrementaMensaje:                                     
                                    b1        36          0, 1, 2, ···
            AnulaMensaje:                                          
                                    b1        0           0, 1, 2, ···
            CambiaSerie:                                           
                                    b2        1           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b2        2           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b2        3           0, 1, 2, ···

                · · · · · · · · · ·                                

            IncrementaMensaje:                                     
                                    b2        máximo      0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b2        0           0, 1, 2, ···
            CambiaSerie:                                           
                                    b3        1           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b3        2           0, 1, 2, ···
            IncrementaMensaje:                                     
                                    b3        3           0, 1, 2, ···

                · · · · · · · · · · 

        */


        private static void Valida () {
            ContadorCTR CTR = new ContadorCTR (); 
            ValidaIniciaSerie       (CTR);
            ValidaCambiaSerie       (CTR, 0x1F2F3F4F5F6F7F8F);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            ValidaAnulaMensaje      (CTR);
            ValidaCambiaSerie       (CTR, 0x7E8E9EAEBECEDEEE);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            ValidaCambiaSerie       (CTR, 0x1122334455667788);
            ValidaIncrementeMensaje (CTR);
            ValidaIncrementeMensaje (CTR);
            Console.ReadLine ();
        }


        private static void ValidaIniciaSerie (ContadorCTR CTR) {
            Console.WriteLine ();
            Console.WriteLine ("mensaje:");
            CTR.Inicia ();
            Imprime (CTR);
            for (int i = 1; i < 4; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }
        }


        private static void ValidaCambiaSerie (ContadorCTR CTR, long serie) {
            Console.WriteLine ();
            Console.WriteLine ("mensaje:");
            CTR.CambiaSerie (serie);
            Imprime (CTR);
            for (int i = 1; i < 4; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }
        }


        private static void ValidaIncrementeMensaje (ContadorCTR CTR) {
            Console.WriteLine ();
            Console.WriteLine ("mensaje:");
            CTR.IncrementaMensaje ();
            Imprime (CTR);
            for (int i = 1; i < 4; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }
        }


        private static void ValidaAnulaMensaje (ContadorCTR CTR) {
            Console.WriteLine ();
            Console.WriteLine ("mensaje:");
            CTR.AnulaMensaje ();
            Imprime (CTR);
            for (int i = 1; i < 4; ++ i) {
                CTR.IncrementaBloque ();
                Imprime (CTR);
            }
        }


        private static void Imprime (ContadorCTR CTR) {
            Console.Write ("    ");
            Buzon contador = new Buzon ();
            contador.Reserva (ContadorCTR.BytesContador);
            CTR.AsignaContador (contador);
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
            byte [] datos = algoritmo.Decrypt (cifrado.Datos, RSAEncryptionPadding.OaepSHA512);
            //
            #if DEBUG
            if (mensaje.Longitud > 0) {
                Depuracion.Asevera (datos.Length <= mensaje.Longitud);
            }
            #endif
            //
            if (mensaje.Longitud == 0) {
                mensaje.Construye (datos);
            } else {
                Buffer.BlockCopy (datos, 0, mensaje.Datos, mensaje.Inicio, datos.Length);
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
