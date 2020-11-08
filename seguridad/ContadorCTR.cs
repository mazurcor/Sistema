//------------------------------------------------------------------------------
// archivo:     Sistema/seguridad/ContadorCTR.cs
// versión:     28-Oct-2020, terminado, comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Security.Cryptography;
using System.Text;


namespace com.mazc.Sistema {


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
        //private byte [] buzon_contador;

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
            //buzon_contador = new byte [BytesContador];
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
            //PonNumeroBuzon (numero_serie,   inicio_serie);
            //PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            //PonNumeroBuzon (numero_bloque,  inicio_bloque);
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
            if (numero_serie != 0 || numero_mensaje != 0 || numero_bloque != 0) {
                Depuracion.Asevera (contador_leido);
            }
            Depuracion.Asevera (numero_mensaje == 0);
            Depuracion.Asevera (serie != 0);
            Depuracion.Asevera (numero_serie != serie);
            //
            numero_serie   = serie;
            numero_mensaje = 1;
            numero_bloque  = 0;
            //
            //PonNumeroBuzon (numero_serie,   inicio_serie);
            //PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            //PonNumeroBuzon (numero_bloque,  inicio_bloque);
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
            // se anula el mensaje tras cambiar la serie, cuando el contador no está leido:
            //Depuracion.Asevera (contador_leido);
            Depuracion.Asevera (numero_serie != 0);
            Depuracion.Asevera (numero_mensaje > 0);
            //
            numero_mensaje = 0;
            numero_bloque  = 0;
            //
            //PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            //PonNumeroBuzon (numero_bloque,  inicio_bloque);
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
            //PonNumeroBuzon (numero_mensaje, inicio_mensaje);
            //PonNumeroBuzon (numero_bloque,  inicio_bloque);
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
            //PonNumeroBuzon (numero_bloque,  inicio_bloque);
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
            PonNumeroBuzon (numero_serie,   inicio_serie,   destino);
            PonNumeroBuzon (numero_mensaje, inicio_mensaje, destino);
            PonNumeroBuzon (numero_bloque,  inicio_bloque,  destino);
            //Buffer.BlockCopy (buzon_contador, 0, destino.Datos, destino.Inicio, BytesContador);
            //
            contador_leido = true;
        }


        #region métodos privados


        // Pone en el buzon del contador la marca de serie actual.
        private void PonNumeroBuzon (long numero, int inicio, Buzon destino) {
            destino [inicio    ] = (byte) (numero_serie >> 56);
            destino [inicio + 1] = (byte) (numero_serie >> 48);
            destino [inicio + 2] = (byte) (numero_serie >> 40);
            destino [inicio + 3] = (byte) (numero_serie >> 32);
            destino [inicio + 4] = (byte) (numero_serie >> 24);
            destino [inicio + 5] = (byte) (numero_serie >> 16);
            destino [inicio + 6] = (byte) (numero_serie >>  8);
            destino [inicio + 7] = (byte) (numero_serie      );
        }


        // Pone en el buzón del contador el número indicado en la posición indicada.
        private void PonNumeroBuzon (int numero, int inicio, Buzon destino) {
            destino [inicio    ] = (byte) (numero >> 24);
            destino [inicio + 1] = (byte) (numero >> 16);
            destino [inicio + 2] = (byte) (numero >>  8);
            destino [inicio + 3] = (byte) (numero      );
        }


        #endregion


        #region métodos privados


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


        // ATENCIÓN: 
        //      para que funcione esta prueba hay que poner:
        //      internal const int MaximoMensaje = 5;//int.MaxValue;
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


}
