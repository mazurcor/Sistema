//------------------------------------------------------------------------------
// archivo:     Sistema/Buzon.cs
// versión:     22-Oct-2020
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Text;


namespace com.mazc.Sistema {


    internal struct Buzon {


        #region variables privadas

        // si es nulo, es un buzon de longitud 0
        private byte [] almacen;
        private int     inicio;
        private int     longitud;

        // si es > 0, hay buzones que son fragmentos de este buzon
        // si es = 0, no hay buzones que son fragmentos de este buzon
        // si es < 0, este es un fragmento de otro buzon
        private int fragmentos;

        #endregion


        internal byte [] Almacen {
            get {
                return this.almacen;
            }
        }


        internal int Inicio {
            get {
                return this.inicio;
            }
        }


        internal int Longitud {
            get {
                return this.longitud;
            }
        }


        internal bool Fragmento {
            get {
                return fragmentos < 0;
            }
        }


        internal void Reserva (int longitud_) {
            #if DEBUG
            Depuracion.Valida (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Valida (longitud_ <= 0, "'longitud_' inválida.");
            #endif
            //
            this.almacen    = new byte [longitud_];
            this.inicio     = 0;
            this.longitud   = longitud_;
            this.fragmentos = 0;
        }


        internal void ReservaCopia (byte [] datos) {
            #if DEBUG
            Depuracion.Valida (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Valida (datos == null, "'datos' nulo.");
            Depuracion.Valida (datos.Length == 0, "Longitud de 'datos' inválida.");
            #endif
            //
            this.almacen    = new byte [datos.Length];
            this.inicio     = 0;
            this.longitud   = datos.Length;
            this.fragmentos = 0;
            //
            Buffer.BlockCopy (datos, 0, this.almacen, 0, datos.Length);
        }


        internal void ReservaCopia (string cadena) {
            #if DEBUG
            Depuracion.Valida (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Valida (cadena == null, "'cadena' nulo.");
            Depuracion.Valida (cadena.Length == 0, "Longitud de 'cadena' inválida.");
            #endif
            //
            this.almacen    = new byte [cadena.Length * 2];
            this.inicio     = 0;
            this.longitud   = cadena.Length * 2;
            this.fragmentos = 0;
            //
            PonString (0, cadena);
        }


        internal void Libera () {
            if (this.almacen == null) {
                return;
            }
            //
            #if DEBUG
            // no actua en buzón vacío
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos > 0, "Quedan fragmentos de este 'Buzon'.");
            #endif
            //
            this.almacen    = null;
            this.inicio     = 0;
            this.longitud   = 0;
            this.fragmentos = 0;
        }


        internal void CreaFragmento (int inicio_, int longitud_, ref Buzon fragmento) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (fragmento.almacen != null, "'fragmento' no vacío");
            Depuracion.Valida (inicio_ < 0, "'inicio' inválido.");
            Depuracion.Valida (longitud_ <= 0, "'longitud' inválida.");
            Depuracion.Valida (inicio_ + longitud_ - 1 >= this.longitud, "'longitud' excesivo.");
            #endif
            //
            fragmento.almacen    = this.almacen;
            fragmento.inicio     = inicio_;
            fragmento.longitud   = longitud_;
            fragmento.fragmentos = -1;
            this.fragmentos ++;
        }


        internal void AnulaFragmento (ref Buzon fragmento) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Valida (fragmento.almacen == null, "'fragmento' vacío");
            Depuracion.Valida (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Valida (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            #endif
            //
            fragmento.almacen    = null;
            fragmento.inicio     = 0;
            fragmento.longitud   = 0;
            fragmento.fragmentos = 0;
            this.fragmentos --;
        }


        internal void ResituaFragmento (ref Buzon fragmento, int medida) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Valida (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Valida (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Valida (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            // this.inicio será 0
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            poscn_fragm += medida;
            final_fragm += medida;
            Depuracion.Valida (poscn_fragm < 0, "'fragmento' se situa fuera");
            Depuracion.Valida (this.longitud - 1 < final_fragm, "'medida' inválida.");
            #endif
            //
            fragmento.inicio += medida;
        }


        internal void RedimensionaFragmento (ref Buzon fragmento, int medida) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Valida (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Valida (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Valida (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            // this.inicio será 0
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            final_fragm += medida;
            Depuracion.Valida (final_fragm < poscn_fragm, "'medida' inválida.");
            Depuracion.Valida (this.longitud - 1 < final_fragm, "'fragmento' se situa fuera");
            #endif
            //
            fragmento.inicio += medida;
        }


        internal void TrasponBuzon (ref Buzon origen) {
            #if DEBUG
            // admite buzon vacío y no vacío
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos > 0, "Quedan fragmentos de este 'Buzon'.");
            Depuracion.Valida (origen.almacen == null, "'origen' vacío.");
            Depuracion.Valida (origen.fragmentos < 0, "'origen' es fragmento de otro 'Buzon'.");
            Depuracion.Valida (origen.fragmentos > 0, "Quedan fragmentos de 'origen'.");
            #endif
            //
            this.almacen    = origen.almacen;
            this.inicio     = origen.inicio;
            this.longitud   = origen.longitud;
            this.fragmentos = origen.fragmentos;
            origen.almacen    = null;
            origen.inicio     = 0;
            origen.longitud   = 0;
            origen.fragmentos = 0;
        }


        internal static bool DatosIguales (in Buzon primero, in Buzon segundo) {
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


        internal static void CopiaDatos (in Buzon origen, in Buzon destino, int longitud_) {
            #if DEBUG
            Depuracion.Valida (origen .almacen == null, "'origen' vacío");
            Depuracion.Valida (destino.almacen == null, "'destino' vacío");
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


        internal void Blanquea () {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
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


        internal void PonByte (int posicion, byte numero) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 1);
            #endif
            //
            this.almacen [this.inicio + posicion] = numero;
        }


        internal byte TomaByte (int posicion) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 1);
            #endif
            //
            return this.almacen [this.inicio + posicion];
        }


        internal void PonShort (int posicion, short numero) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 2);
            #endif
            //
            int primero = this.inicio + posicion;
            this.almacen [primero    ] = (byte) (numero >> 8);
            this.almacen [primero + 1] = (byte) (numero);
        }


        internal short TomaShort (int posicion) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 2);
            #endif
            //
            int primero = this.inicio + posicion;
            return (short) (((this.almacen [primero    ] & 0xff) << 8) |
                            ((this.almacen [primero + 1] & 0xff)     )  );
        }


        internal void PonInt (int posicion, int numero) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 4);
            #endif
            //
            int primero = this.inicio + posicion;
            this.almacen [primero    ] = (byte) (numero >> 24);
            this.almacen [primero + 1] = (byte) (numero >> 16);
            this.almacen [primero + 2] = (byte) (numero >>  8);
            this.almacen [primero + 3] = (byte) (numero      );
        }


        internal int TomaInt (int posicion) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 4);
            #endif
            //
            int primero = this.inicio + posicion;
            return ((this.almacen [primero    ]       ) << 24) |
                   ((this.almacen [primero + 1] & 0xff) << 16) |
                   ((this.almacen [primero + 2] & 0xff) <<  8) |
                   ((this.almacen [primero + 3] & 0xff)      );
        }


        internal void PonLong (int posicion, long numero) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
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


        internal long TomaLong (int posicion) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
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


        internal void PonString (int posicion, string cadena) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (cadena == null, "'cadena' nula");
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


        internal void TomaString (int posicion, int longitud_, StringBuilder cadena) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (cadena == null, "'cadena' nula");
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


        #region métodos privados


        private void ValidaRango (int posicion_, int longitud_) {
            Depuracion.Valida (posicion_ < 0, "'posicion' inválida.");
            Depuracion.Valida (longitud_ < 0, "'longitud' inválida.");
            Depuracion.Valida (posicion_ + longitud_ - 1 <= this.longitud, "'posicion' o 'longitud' inválidas.");
        }


        #endregion


    }


}
