//------------------------------------------------------------------------------
// archivo:     Sistema/Buzon.cs
// versión:     27-Oct-2020, terminado y comentado.
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Text;


namespace com.mazc.Sistema {


    // Encapsula un array de bytes. 
    // Tambien puede ser una porción secuencial del array de bytes de otra instancia de 'Buzon'.
    // Es una clase de utilidad que simplifica la implementación de los componentes de 
    // 'com.mazc.Sistema'.
    internal sealed class Buzon {


        #region variables privadas

        // si es nulo, es un buzon de longitud 0
        private byte [] almacen;
        private int     inicio;
        private int     longitud;

        // si es > 0, hay buzones que son porciones de este buzon
        // si es = 0, no hay buzones que son porciones de este buzon
        // si es < 0, este es un porción de otro buzon
        private int porciones;

        #endregion


        // Array de bytes encapsulado en esta instancia. 
        // Si esta instancia es una porción de otra instancia, es el array de esta última.
        internal byte [] Datos {
            get {
                return this.almacen;
            }
        }


         
        internal int Inicio {
            get {
                return this.inicio;
            }
        }


        // Longitud en bytes del array encapsulado.
        // Si es porción, es la longitud del segmento de bytes. Si no es una porción, es la longitud
        // del array de bytes.
        internal int Longitud {
            get {
                return this.longitud;
            }
        }


        // Indica si esta instancia es una porción de otra instancia de 'Buzon'.
        internal bool EsPorcion {
            get {
                return porciones < 0;
            }
        }


        // Devuelve y asigna un byte del array encapsulado, el situado en la posicion indicada.
        // Su es una porción, se toma la posición a partir del inicio de la porción.
        // No puede ser una instancia vacía.
        internal byte this [int posicion] {
            get {
                #if DEBUG
                Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
                ValidaRango (posicion, 1);
                #endif
                //
                return this.almacen [this.inicio + posicion];
            }
            set {
                #if DEBUG
                Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
                ValidaRango (posicion, 1);
                #endif
                //
                this.almacen [this.inicio + posicion] = value;
            }
        }


        // Reserva memoria para un array de bytes de la longitud indicada y lo encapsula en la instancia.
        // La instancia debe estar previamente vacía.
        internal void Reserva (int longitud_) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (longitud_ <= 0, "'longitud_' inválida.");
            #endif
            //
            this.almacen    = new byte [longitud_];
            this.inicio     = 0;
            this.longitud   = longitud_;
            this.porciones = 0;
        }


        // Encapsula en esta instancia el array de bytes indicado. 
        // No se debe encapsular el mismo array de bytes en dos instancias distintas. Para ello 
        // están las porciones.
        // La instancia debe estar previamente vacía. 'datos' no puede tener longitud cero. 
        internal void Construye (byte [] datos) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (datos == null, "'datos' nulo.");
            Depuracion.Depura (datos.Length == 0, "Longitud de 'datos' inválida.");
            #endif
            //
            this.almacen    = datos;
            this.inicio     = 0;
            this.longitud   = datos.Length;
            this.porciones = 0;
        }


        // Reserva memoria para un array de bytes, lo encapsula en la instancia y copia el array de 
        // bytes 'datos' en él.
        // La instancia debe estar previamente vacía. 'datos' no puede tener longitud cero.
        internal void ReservaYCopia (byte [] datos) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (datos == null, "'datos' nulo.");
            Depuracion.Depura (datos.Length == 0, "Longitud de 'datos' inválida.");
            #endif
            //
            this.almacen    = new byte [datos.Length];
            this.inicio     = 0;
            this.longitud   = datos.Length;
            this.porciones = 0;
            //
            Buffer.BlockCopy (datos, 0, this.almacen, 0, datos.Length);
        }


        // Reserva memoria para un array de bytes, lo encapsula en la instancia y escribe la cadena de 
        // caracteres en él.
        // Cada caracter de 'datos' se escribe en dos bytes del array, el formato usado es 
        // 'big-endian'. Por tanto, la longitud del array de bytes es el doble que la de la cadena 
        // de caracteres.
        // La instancia debe estar previamente vacía. 'datos' no puede tener longitud cero.
        internal void ReservaYCopia (string cadena) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (cadena == null, "'cadena' nulo.");
            Depuracion.Depura (cadena.Length == 0, "Longitud de 'cadena' inválida.");
            #endif
            //
            this.almacen    = new byte [cadena.Length * 2];
            this.inicio     = 0;
            this.longitud   = cadena.Length * 2;
            this.porciones = 0;
            //
            PonString (0, cadena);
        }


        // Libera la memoria usada por esta instancia, dejandola vacía.
        // Esta instancia no puede ser una porción, ni debe haber porciones de esta instancia.
        internal void Libera () {
            if (this.almacen == null) {
                return;
            }
            //
            #if DEBUG
            // no actua en buzón vacío
            Depuracion.Depura (this.porciones < 0, "Este es porcion de otro 'Buzon'.");
            Depuracion.Depura (this.porciones > 0, "Quedan porciones de este 'Buzon'.");
            #endif
            //
            this.almacen   = null;
            this.inicio    = 0;
            this.longitud  = 0;
            this.porciones = 0;
        }


        // Tansforma un buzón en una porción que encapsula un rango del array de bytes de esta 
        // intancia.
        // El buzón a transformar, 'porcion',  debe estar vacío.
        // La instancia no puede estar vacía ni ser una porción de otro buzón. 'inicio' y 
        // 'longitud' deben designar un rango válido en el array de bytes. 
        // En la instancia queda anotado que hay una porción mas creada sobre ella.
        internal void ConstruyePorcion (int posicion, int longitud, Buzon porcion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.porciones < 0, "Este es porcion de otro 'Buzon'.");
            ValidaRango (posicion, longitud);
            Depuracion.Depura (porcion == null, "'porcion' nulo.");
            Depuracion.Depura (porcion.almacen != null, "'porcion' no vacío.");
            #endif
            //
            porcion.almacen    = this.almacen;
            porcion.inicio     = posicion;
            porcion.longitud   = longitud;
            porcion.porciones = -1;
            this.porciones ++;
        }


        // Anula una porción de esta instancia, dejandola vacía.
        // El buzón anulado ('porcion') debe ser una porción previamente construida sobre esta 
        // instancia.
        // En la instancia queda anotado que hay una porción menos creada sobre ella.
        internal void AnulaPorcion (Buzon porcion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.porciones < 0, "Este es porcion de otro 'Buzon'.");
            Depuracion.Depura (this.porciones == 0, "Este no tiene porciones.");
            Depuracion.Depura (porcion == null, "'porcion' nulo");
            Depuracion.Depura (porcion.almacen == null, "'porcion' vacío");
            Depuracion.Depura (porcion.porciones >= 0, "'porcion' no es un porcion'");
            Depuracion.Depura (porcion.almacen != this.almacen, 
                               "'porcion' no es porcion de este");
            #endif
            //
            porcion.almacen   = null;
            porcion.inicio    = 0;
            porcion.longitud  = 0;
            porcion.porciones = 0;
            this.porciones --;
        }


        // Cambia una porción de esta instancia, desplazando el rango del array de bytes, en la 
        // medida indicada.
        // El buzón cambiado ('porcion') debe ser una porción previamente construida sobre esta 
        // instancia.
        // Tras el cambio, 'porcion' debe designar un rango válido en el array de bytes. 
        internal void ResituaPorcion (Buzon porcion, int medida) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.porciones < 0, "Este es porcion de otro 'Buzon'.");
            Depuracion.Depura (this.porciones == 0, "Este no tiene porciones.");
            Depuracion.Depura (porcion == null, "'porcion' nulo");
            Depuracion.Depura (porcion.almacen == null, "'porcion' es vacío");
            Depuracion.Depura (porcion.porciones >= 0, "'porcion' no es un porción'");
            Depuracion.Depura (porcion.almacen != this.almacen, 
                               "'porcion' no es porcion de este");
            // this.inicio será 0
            int poscn_fragm = porcion.inicio;
            int final_fragm = porcion.inicio + porcion.longitud - 1;
            poscn_fragm += medida;
            final_fragm += medida;
            Depuracion.Depura (poscn_fragm < 0, "'porcion' se situa fuera");
            Depuracion.Depura (this.longitud - 1 < final_fragm, "'medida' inválida.");
            #endif
            //
            porcion.inicio += medida;
        }


        // Cambia una porción de esta instancia, modificando la longitud del rango del array de 
        // bytes, en la medida indicada.
        // El buzón cambiado ('porcion') debe ser una porción previamente construida sobre esta 
        // instancia.
        // Tras el cambio, 'porcion' debe designar un rango válido en el array de bytes. 
        internal void RedimensionaPorcion (Buzon porcion, int medida) {
            #if DEBUG
            Depuracion.Depura (porcion == null, "'porcion' nulo");
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.porciones < 0, "Este es porcion de otro 'Buzon'.");
            Depuracion.Depura (this.porciones == 0, "Este no tiene porciones.");
            Depuracion.Depura (porcion.almacen == null, "'porcion' es vacío");
            Depuracion.Depura (porcion.porciones >= 0, "'porcion' no es un porcion'");
            Depuracion.Depura (porcion.almacen != this.almacen, 
                               "'porcion' no es porcion de este");
            // this.inicio será 0
            int poscn_fragm = porcion.inicio;
            int final_fragm = porcion.inicio + porcion.longitud - 1;
            final_fragm += medida;
            Depuracion.Depura (final_fragm < poscn_fragm, "'medida' inválida.");
            Depuracion.Depura (this.longitud - 1 < final_fragm, "'porcion' se situa fuera");
            #endif
            //
            porcion.longitud += medida;
        }


        // Traslada el array de bytes encapsulado desde el buzón indicado, hasta esta instancia.
        // Esta instancia se vacía antes del traslado. 'origen' queda vacío tras el traslado.
        // Ni esta instancia ni 'origen' pueden ser porciones, ni pueden tener porciones construidas 
        // sobre ellos.
        internal void TrasponBuzon (Buzon origen) {
            #if DEBUG
            // admite buzon vacío y no vacío
            Depuracion.Depura (this.porciones < 0, "Este es porción de otro 'Buzon'.");
            Depuracion.Depura (this.porciones > 0, "Quedan porciones de este 'Buzon'.");
            Depuracion.Depura (origen == null, "'origen' nulo");
            Depuracion.Depura (origen.almacen == null, "'origen' vacío.");
            Depuracion.Depura (origen.porciones < 0, "'origen' es porcion de otro 'Buzon'.");
            Depuracion.Depura (origen.porciones > 0, "Quedan porciones de 'origen'.");
            #endif
            //
            this.almacen     = origen.almacen;
            this.inicio      = origen.inicio;
            this.longitud    = origen.longitud;
            this.porciones   = origen.porciones;
            origen.almacen   = null;
            origen.inicio    = 0;
            origen.longitud  = 0;
            origen.porciones = 0;
        }


        // Compara los arrays de bytes de dos buzones devolviendo si son iguales.
        // Compara también buzones vacíos'.
        internal static bool DatosIguales (Buzon primero, Buzon segundo) {
            // admite buzones vacios o no
            //
            if (primero.longitud != segundo.longitud) {
                return false;
            } 
            int indice_1 = primero.inicio;
            int indice_2 = segundo.inicio;
            int longitud = primero.longitud;
            while (longitud > 0) {
                if (primero.almacen [indice_1] != segundo.almacen [indice_2]) {
                    return false;
                }
                indice_1 ++;
                indice_2 ++;
                longitud --;
            }
            return true;
        }


        // Copia el array de bytes de un buzón en otro buzón.
        // Los buzones deben ser de la misma longitud y no puede ser vacíos.
        // Los buzones puede ser porciones (uno o los dos). En tal caso se copia el rango que 
        // especifican.
        internal static void CopiaDatos (Buzon origen, Buzon destino) {
            #if DEBUG
            Depuracion.Depura (origen  == null, "'origen' nulo");
            Depuracion.Depura (destino == null, "'destino' nulo");
            Depuracion.Depura (origen .almacen == null, "'origen' vacío");
            Depuracion.Depura (destino.almacen == null, "'destino' vacío");
            Depuracion.Depura (origen.longitud != destino.longitud, "'origen' y 'destino' de longitudes distintas");
            #endif
            //
            int indice_origen  = origen.inicio;
            int indice_destino = destino.inicio;
            int longitud = origen.longitud;
            while (longitud > 0) {
                destino.almacen [indice_destino] = origen.almacen [indice_origen];
                indice_origen ++;
                indice_destino ++;
                longitud --;
            }
        }


        // Copia una parte del array de bytes de un buzón en otro buzón. 
        // El rango de bytes a copiar, tanto en 'origen' como en 'destino', es de 0 a 'longitud_'-1. 
        // El rango debe ser válido en ambos buzones.
        // Los buzones puede ser porciones (uno o los dos). En tal caso, el rango a copiar se toma 
        // dentro del rango de la porción.
        internal static void CopiaDatos (Buzon origen, Buzon destino, int longitud_) {
            #if DEBUG
            Depuracion.Depura (origen  == null, "'origen' nulo");
            Depuracion.Depura (destino == null, "'destino' nulo");
            Depuracion.Depura (origen .almacen == null, "'origen' vacío");
            Depuracion.Depura (destino.almacen == null, "'destino' vacío");
            origen .ValidaRango (0, longitud_);
            destino.ValidaRango (0, longitud_);
            #endif
            //
            int indice_origen  = origen.inicio;
            int indice_destino = destino.inicio;
            while (longitud_ > 0) {
                destino.almacen [indice_destino] = origen.almacen [indice_origen];
                indice_origen ++;
                indice_destino ++;
                longitud_ --;
            }
        }


        // Asigna 0 a los bytes del array encapsulado en esta instancia.
        // Esta instancia no puede ser vacía.
        internal void Blanquea () {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            #endif
            //
            int indice    = this.inicio;
            int longitud_ = this.longitud;
            while (longitud_ > 0) {
                this.almacen [indice] = 0;
                indice ++;
                longitud_ --;
            }
        }


        // Escribe en el array del buzón la representación en bytes del número. 
        // El formato usado es 'big-endian'.
        // Se escriben 2 bytes en la posición indicada, el rango escrito debe estar dentro del array 
        // de bytes de la instancia.
        internal void PonShort (int posicion, short numero) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 2);
            #endif
            //
            int primero = this.inicio + posicion;
            this.almacen [primero    ] = (byte) (numero >> 8);
            this.almacen [primero + 1] = (byte) (numero);
        }


        // Lee del array del buzón la representación en bytes de un entero corto. 
        // El formato usado es 'big-endian'.
        // Se leen 2 bytes de la posición indicada, el rango leido debe estar dentro del array 
        // de bytes de la instancia.
        internal short TomaShort (int posicion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 2);
            #endif
            //
            int primero = this.inicio + posicion;
            return (short) (((this.almacen [primero    ] & 0xff) << 8) |
                            ((this.almacen [primero + 1] & 0xff)     )  );
        }


        // Escribe en el array del buzón la representación en bytes del número. 
        // El formato usado es 'big-endian'.
        // Se escriben 4 bytes en la posición indicada, el rango escrito debe estar dentro del array 
        // de bytes de la instancia.
        internal void PonInt (int posicion, int numero) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 4);
            #endif
            //
            int primero = this.inicio + posicion;
            this.almacen [primero    ] = (byte) (numero >> 24);
            this.almacen [primero + 1] = (byte) (numero >> 16);
            this.almacen [primero + 2] = (byte) (numero >>  8);
            this.almacen [primero + 3] = (byte) (numero      );
        }


        // Lee del array del buzón la representación en bytes de un entero. 
        // El formato usado es 'big-endian'.
        // Se leen 4 bytes de la posición indicada, el rango leido debe estar dentro del array 
        // de bytes de la instancia.
        internal int TomaInt (int posicion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 4);
            #endif
            //
            int primero = this.inicio + posicion;
            return ((this.almacen [primero    ]       ) << 24) |
                   ((this.almacen [primero + 1] & 0xff) << 16) |
                   ((this.almacen [primero + 2] & 0xff) <<  8) |
                   ((this.almacen [primero + 3] & 0xff)      );
        }


        // Escribe en el array del buzón la representación en bytes del número. 
        // El formato usado es 'big-endian'.
        // Se escriben 8 bytes en la posición indicada, el rango escrito debe estar dentro del array 
        // de bytes de la instancia.
        internal void PonLong (int posicion, long numero) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 8);
            #endif
            //
            int primero = this.inicio + posicion;
            this.almacen [primero    ] = (byte) (numero >> 56);
            this.almacen [primero + 1] = (byte) (numero >> 48);
            this.almacen [primero + 2] = (byte) (numero >> 40);
            this.almacen [primero + 3] = (byte) (numero >> 32);
            this.almacen [primero + 4] = (byte) (numero >> 24);
            this.almacen [primero + 5] = (byte) (numero >> 16);
            this.almacen [primero + 6] = (byte) (numero >>  8);
            this.almacen [primero + 7] = (byte) (numero      );
        }


        // Lee del array del buzón la representación en bytes de un entero largo. 
        // El formato usado es 'big-endian'.
        // Se leen 8 bytes de la posición indicada, el rango leido debe estar dentro del array 
        // de bytes de la instancia.
        internal long TomaLong (int posicion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 8);
            #endif
            //
            int primero = this.inicio + posicion;
            return ((((long) this.almacen [primero    ])       ) << 56) |
                   ((((long) this.almacen [primero + 1]) & 0xff) << 48) |
                   ((((long) this.almacen [primero + 2]) & 0xff) << 40) |
                   ((((long) this.almacen [primero + 3]) & 0xff) << 32) |
                   ((((long) this.almacen [primero + 4]) & 0xff) << 24) |
                   ((((long) this.almacen [primero + 5]) & 0xff) << 16) |
                   ((((long) this.almacen [primero + 6]) & 0xff) <<  8) |
                   ((((long) this.almacen [primero + 7]) & 0xff)       );
        }


        // Escribe la cadena de caracteres en el array del buzón. 
        // Cada caracter se escribe en dos bytes del array, el formato usado es 'big-endian'. Por 
        // tanto, el número de bytes escritos es el doble de la longitud de la cadena de caracteres.
        // Se escriben los bytes en la posición indicada, el rango escrito debe estar dentro del 
        // array de bytes de la instancia.
        internal void PonString (int posicion, string cadena) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (cadena == null, "'cadena' nula");
            ValidaRango (posicion, cadena.Length * 2);
            #endif
            //
            int destino = this.inicio + posicion;
            for (int indice = 0; indice < cadena.Length; ++ indice) {
                char caracter = cadena [indice];
                this.almacen [destino    ] = (byte) (caracter >> 8);
                this.almacen [destino + 1] = (byte) (caracter     );
                destino += 2;
            }
        }


        // Lee una serie de caracteres del array del buzón y los escribe en una cadena caracteres. 
        // Cada caracter de se lee de dos bytes del array, el formato usado es 'big-endian'.  
        // El número de caracteres leidos es 'longitud_' y el número de bytes leidos es el doble.
        // Se lee los bytes de la posición indicada, el rango leido debe estar dentro del array de 
        // bytes de la instancia.
        // Antes de escribir los caracteres en 'cadena', esta se vacía.
        internal void TomaString (int posicion, int longitud_, StringBuilder cadena) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (cadena == null, "'cadena' nula");
            ValidaRango (posicion, longitud_ * 2);
            #endif
            //
            cadena.Length = 0;
            int indice = this.inicio + posicion;
            for (int cuenta = 0; cuenta < longitud_; ++ cuenta) {
                char caracter =
                        (char) (((this.almacen [indice    ] & 0xff) << 8) |
                                ((this.almacen [indice + 1] & 0xff)     )  );
                cadena.Append (caracter);
                indice += 2;
            }
        }


        // Escribe la secuencia de bytes en el array del buzón. 
        // Los bytes escritos se toman de 'binario'. El número de bytes escritos es su longitud, que 
        // no puede ser cero.
        // Se escriben los bytes en la posición indicada, el rango escrito debe estar dentro del 
        // array de bytes de la instancia.
        internal void PonBinario (int posicion, byte [] binario) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (binario == null, "'binario' nula");
            Depuracion.Depura (binario.Length == 0, "'binario' vacío");
            ValidaRango (posicion, binario.Length);
            #endif
            //
            int destino = this.inicio + posicion;
            Buffer.BlockCopy (binario, 0, this.almacen, destino, binario.Length);
        }


        // Lee una secuencia de bytes del array del buzón. 
        // Los bytes leidos se escriben en 'binario'. El número de bytes leidos es su longitud, que 
        // no puede ser cero.
        // Se lee los bytes de la posición indicada, el rango leido debe estar dentro del array de 
        // bytes de la instancia.
        internal void TomaBinario (int posicion, byte [] binario) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (binario == null, "'binario' nula");
            Depuracion.Depura (binario.Length == 0, "'binario' vacío");
            ValidaRango (posicion, binario.Length);
            #endif
            //
            int destino = this.inicio + posicion;
            Buffer.BlockCopy (this.almacen, destino, binario, 0, binario.Length);
        }


        //private string [] digitos = new string [256] {
        //        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",  
        //        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",  
        //        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",  
        //        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",  
        //        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",  
        //        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",  
        //        "50", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",  
        //        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",  
        //        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",  
        //        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",  
        //        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",  
        //        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",  
        //        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",  
        //        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",  
        //        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",  
        //        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF" };

        private static char [] digito = new char [] { 
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        public override string ToString () {
            StringBuilder cadena = new StringBuilder ();
            int indice = this.inicio;
            int cuenta = this.longitud;
            while (cuenta > 0) {
                byte valor = this.almacen [indice];
                cadena.Append (digito [(valor & 0xf0) >> 4]);
                cadena.Append (digito [ valor & 0x0f      ]);
                indice ++;
                cuenta --;
            }
            return cadena.ToString ();
        }


        #region métodos privados


        private void ValidaRango (int posicion_, int longitud_) {
            Depuracion.Depura (posicion_ < 0, "'posicion' inválida.");
            Depuracion.Depura (longitud_ <= 0, "'longitud' inválida.");
            Depuracion.Depura (this.longitud <= posicion_ + longitud_ - 1, "'posicion' o 'longitud' inválidas.");
        }


        #endregion


    }


}
