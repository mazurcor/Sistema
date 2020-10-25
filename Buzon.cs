//------------------------------------------------------------------------------
// archivo:     Sistema/Buzon.cs
// versión:     25-Oct-2020
// autor:       M. A. Zurita Cortés (mazurcor@gmail.com)
// licencia:    Licencia Pública General de GNU, versión 3
//------------------------------------------------------------------------------
 

using System;
using System.Text;


namespace com.mazc.Sistema {


    internal sealed class Buzon {


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
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (longitud_ <= 0, "'longitud_' inválida.");
            #endif
            //
            this.almacen    = new byte [longitud_];
            this.inicio     = 0;
            this.longitud   = longitud_;
            this.fragmentos = 0;
        }


        internal void ReservaCopia (byte [] datos) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (datos == null, "'datos' nulo.");
            Depuracion.Depura (datos.Length == 0, "Longitud de 'datos' inválida.");
            #endif
            //
            this.almacen    = new byte [datos.Length];
            this.inicio     = 0;
            this.longitud   = datos.Length;
            this.fragmentos = 0;
            //
            Buffer.BlockCopy (datos, 0, this.almacen, 0, datos.Length);
        }


        internal void ReservaMueve (byte [] datos) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (datos == null, "'datos' nulo.");
            Depuracion.Depura (datos.Length == 0, "Longitud de 'datos' inválida.");
            #endif
            //
            this.almacen    = datos;
            this.inicio     = 0;
            this.longitud   = datos.Length;
            this.fragmentos = 0;
        }


        internal void ReservaCopia (string cadena) {
            #if DEBUG
            Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Depura (cadena == null, "'cadena' nulo.");
            Depuracion.Depura (cadena.Length == 0, "Longitud de 'cadena' inválida.");
            #endif
            //
            this.almacen    = new byte [cadena.Length * 2];
            this.inicio     = 0;
            this.longitud   = cadena.Length * 2;
            this.fragmentos = 0;
            //
            PonString (0, cadena);
        }


        //internal void ReservaCopia (Buzon datos) {
        //    #if DEBUG
        //    Depuracion.Depura (this.almacen != null, "'Buzon' no vacío");
        //    Depuracion.Depura (datos == null, "'datos' nulo.");
        //    Depuracion.Depura (datos.Longitud == 0, "Longitud de 'datos' inválida.");
        //    #endif
        //    //
        //    this.almacen    = new byte [datos.Longitud];
        //    this.inicio     = 0;
        //    this.longitud   = datos.Longitud;
        //    this.fragmentos = 0;
        //    //
        //    Buffer.BlockCopy (datos.almacen, datos.inicio, this.almacen, 0, datos.Longitud);
        //}


        internal void Libera () {
            if (this.almacen == null) {
                return;
            }
            //
            #if DEBUG
            // no actua en buzón vacío
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (this.fragmentos > 0, "Quedan fragmentos de este 'Buzon'.");
            #endif
            //
            this.almacen    = null;
            this.inicio     = 0;
            this.longitud   = 0;
            this.fragmentos = 0;
        }


        internal void CreaFragmento (int inicio_, int longitud_, Buzon fragmento) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (inicio_ < 0, "'inicio' inválido.");
            Depuracion.Depura (longitud_ <= 0, "'longitud' inválida.");
            Depuracion.Depura (inicio_ + longitud_ - 1 >= this.longitud, "'longitud' excesivo.");
            Depuracion.Depura (fragmento == null, "'fragmento' nulo.");
            Depuracion.Depura (fragmento.almacen != null, "'fragmento' no vacío.");
            #endif
            //
            fragmento.almacen    = this.almacen;
            fragmento.inicio     = inicio_;
            fragmento.longitud   = longitud_;
            fragmento.fragmentos = -1;
            this.fragmentos ++;
        }


        internal void AnulaFragmento (Buzon fragmento) {
            #if DEBUG
            Depuracion.Depura (fragmento == null, "'fragmento' nulo");
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Depura (fragmento.almacen == null, "'fragmento' vacío");
            Depuracion.Depura (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Depura (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            #endif
            //
            fragmento.almacen    = null;
            fragmento.inicio     = 0;
            fragmento.longitud   = 0;
            fragmento.fragmentos = 0;
            this.fragmentos --;
        }


        internal void ResituaFragmento (Buzon fragmento, int medida) {
            #if DEBUG
            Depuracion.Depura (fragmento == null, "'fragmento' nulo");
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Depura (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Depura (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Depura (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            // this.inicio será 0
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            poscn_fragm += medida;
            final_fragm += medida;
            Depuracion.Depura (poscn_fragm < 0, "'fragmento' se situa fuera");
            Depuracion.Depura (this.longitud - 1 < final_fragm, "'medida' inválida.");
            #endif
            //
            fragmento.inicio += medida;
        }


        internal void RedimensionaFragmento (Buzon fragmento, int medida) {
            #if DEBUG
            Depuracion.Depura (fragmento == null, "'fragmento' nulo");
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Depura (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Depura (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Depura (fragmento.almacen != this.almacen, 
                               "'fragmento' no es fragmento de este");
            // this.inicio será 0
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            final_fragm += medida;
            Depuracion.Depura (final_fragm < poscn_fragm, "'medida' inválida.");
            Depuracion.Depura (this.longitud - 1 < final_fragm, "'fragmento' se situa fuera");
            #endif
            //
            fragmento.inicio += medida;
        }


        internal void TrasponBuzon (Buzon origen) {
            #if DEBUG
            // admite buzon vacío y no vacío
            Depuracion.Depura (origen == null, "'origen' nulo");
            Depuracion.Depura (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Depura (this.fragmentos > 0, "Quedan fragmentos de este 'Buzon'.");
            Depuracion.Depura (origen.almacen == null, "'origen' vacío.");
            Depuracion.Depura (origen.fragmentos < 0, "'origen' es fragmento de otro 'Buzon'.");
            Depuracion.Depura (origen.fragmentos > 0, "Quedan fragmentos de 'origen'.");
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


        internal void PonByte (int posicion, byte numero) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 1);
            #endif
            //
            this.almacen [this.inicio + posicion] = numero;
        }


        internal byte TomaByte (int posicion) {
            #if DEBUG
            Depuracion.Depura (this.almacen == null, "'Buzon' vacío.");
            ValidaRango (posicion, 1);
            #endif
            //
            return this.almacen [this.inicio + posicion];
        }


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


        #region métodos privados


        private void ValidaRango (int posicion_, int longitud_) {
            Depuracion.Depura (posicion_ < 0, "'posicion' inválida.");
            Depuracion.Depura (longitud_ < 0, "'longitud' inválida.");
            Depuracion.Depura (this.longitud < posicion_ + longitud_ - 1, "'posicion' o 'longitud' inválidas.");
        }


        #endregion


    }


}
