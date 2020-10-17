using System;
using System.Text;


namespace com.mazc.Sistema {


    struct Buzon {


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

       
        internal byte this [int indice] {
            get {
                #if DEBUG
                Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
                Depuracion.Valida (indice < 0, "'indice' inválido.");
                Depuracion.Valida (this.longitud <= this.inicio + indice, "'indice' inválido.");
                #endif
                //
                return this.almacen [this.inicio + indice];
            }
            set {
                #if DEBUG
                Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
                Depuracion.Valida (indice < 0, "'indice' inválido.");
                Depuracion.Valida (this.longitud <= this.inicio + indice, "'indice' inválido.");
                #endif
                //
                this.almacen [this.inicio + indice] = value;
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


        internal void ReservaCopia (in Buzon buzon) {
            #if DEBUG
            Depuracion.Valida (this.almacen != null, "'Buzon' no vacío");
            Depuracion.Valida (buzon.longitud == 0, "Longitud de 'buzon' inválida.");
            #endif
            //
            this.almacen    = new byte [buzon.longitud];
            this.inicio     = 0;
            this.longitud   = buzon.longitud;
            this.fragmentos = 0;
            //
            Buffer.BlockCopy (buzon.almacen, buzon.inicio, this.almacen, 0, buzon.longitud);
        }


        internal void Libera () {
            if (this.almacen == null) {
                return;
            }
            //
            #if DEBUG
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
            Depuracion.Valida (inicio_ < 0, "'inicio' inválido.");
            Depuracion.Valida (longitud_ <= 0, "'longitud' inválida.");
            Depuracion.Valida (inicio_ >= this.longitud, "'inicio' excesivo.");
            Depuracion.Valida (inicio_ + longitud_ - 1 >= this.longitud, "'longitud' excesivo.");
            Depuracion.Valida (fragmento.almacen != null, "'fragmento' no vacío");
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
            Depuracion.Valida (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Valida (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Valida (fragmento.almacen != this.almacen, "'fragmento' no es fragmento de este");
            #endif
            //
            fragmento.almacen    = null;
            fragmento.inicio     = 0;
            fragmento.longitud   = 0;
            fragmento.fragmentos = 0;
            this.fragmentos --;
        }


        internal void TrasponBuzon (ref Buzon origen) {
            #if DEBUG
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos > 0, "Quedan fragmentos de este 'Buzon'.");
            Depuracion.Valida (origen.almacen == null, "'origen' vacío.");
            Depuracion.Valida (origen.fragmentos < 0, "'origen' es fragmento de otro 'Buzon'.");
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


        internal void ResituaFragmento (ref Buzon fragmento, int medida) {
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.fragmentos < 0, "Este es fragmento de otro 'Buzon'.");
            Depuracion.Valida (this.fragmentos == 0, "Este no tiene fragmentos.");
            Depuracion.Valida (fragmento.almacen == null, "'fragmento' es vacío");
            Depuracion.Valida (fragmento.fragmentos >= 0, "'fragmento' no es un fragmento'");
            Depuracion.Valida (fragmento.almacen != this.almacen, "'fragmento' no es fragmento de este");
            //
            int poscn_compl = this.inicio;
            int final_compl = this.inicio + this.longitud - 1;
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            poscn_fragm += medida;
            final_fragm += medida;
            Depuracion.Valida (poscn_fragm < poscn_compl, "'fragmento' se situa fuera");
            Depuracion.Valida (final_compl < final_fragm, "'medida' inválida.");
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
            Depuracion.Valida (fragmento.almacen != this.almacen, "'fragmento' no es fragmento de este");
            //
            int poscn_compl = this.inicio;
            int final_compl = this.inicio + this.longitud - 1;
            int poscn_fragm = fragmento.inicio;
            int final_fragm = fragmento.inicio + fragmento.longitud - 1;
            final_fragm += medida;
            Depuracion.Valida (final_compl < final_fragm, "'fragmento' se situa fuera");
            Depuracion.Valida (final_fragm < poscn_fragm, "'medida' inválida.");
            #endif
            //
            fragmento.inicio += medida;
        }


        internal static bool DatosIguales (in Buzon primero, in Buzon segundo) {
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


        internal static void CopiaDatos (in Buzon origen, ref Buzon destino) {
            #if DEBUG
            Depuracion.Valida (origen .almacen == null, "'origen' vacío");
            Depuracion.Valida (destino.almacen == null, "'destino' vacío");
            Depuracion.Valida (origen.longitud != destino.longitud, "longitudes distintas");
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


        internal static void Copia (in Buzon origen, ref Buzon destino, int longitud_) {
            #if DEBUG
            Depuracion.Valida (origen .almacen == null, "'origen'  vacío");
            Depuracion.Valida (destino.almacen == null, "'destino' vacío");
            Depuracion.Valida (longitud_ < 0, "'longitud_' inválida");
            Depuracion.Valida (origen.longitud  < longitud_, "'longitud_' excesiva");
            Depuracion.Valida (destino.longitud < longitud_, "'longitud_' excesiva");
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
            if (this.almacen == null) {
                return;
            }
            int indice   = this.inicio;
            int longitud_ = this.longitud;
            while (longitud_ > 0) {
                this.almacen [indice] = 0;
                indice ++;
                longitud_ --;
            }
        }


        internal void PonLong (int posicion, long numero) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 8 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
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
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 8 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            return ((((long) this.almacen [primero    ])       ) << 56) |
                   ((((long) this.almacen [primero + 1]) & 0xff) << 48) |
                   ((((long) this.almacen [primero + 2]) & 0xff) << 40) |
                   ((((long) this.almacen [primero + 3]) & 0xff) << 32) |
                   ((((long) this.almacen [primero + 4]) & 0xff) << 24) |
                   ((((long) this.almacen [primero + 5]) & 0xff) << 16) |
                   ((((long) this.almacen [primero + 6]) & 0xff) <<  8) |
                   ((((long) this.almacen [primero + 7]) & 0xff)       );
        }


        internal void PonInt (int posicion, int numero) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 4 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            this.almacen [primero    ] = (byte) (numero >> 24);
            this.almacen [primero + 1] = (byte) (numero >> 16);
            this.almacen [primero + 2] = (byte) (numero >>  8);
            this.almacen [primero + 3] = (byte) (numero      );
        }


        internal int TomaInt (int posicion) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 4 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            return ((this.almacen [primero    ]       ) << 24) |
                   ((this.almacen [primero + 1] & 0xff) << 16) |
                   ((this.almacen [primero + 2] & 0xff) <<  8) |
                   ((this.almacen [primero + 3] & 0xff)      );
        }


        internal void PonShort (int posicion, short numero) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 2 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            this.almacen [primero    ] = (byte) (numero >> 8);
            this.almacen [primero + 1] = (byte) (numero);
        }


        internal short TomaShort (int posicion) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 2 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            return (short) (((this.almacen [primero    ] & 0xff) << 8) |
                            ((this.almacen [primero + 1] & 0xff)     )  );
        }


        internal void PonByte (int posicion, byte numero) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 1 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            this.almacen [primero] = numero;
        }


        internal byte TomaByte (int posicion) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 1 - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            return this.almacen [primero];
        }


        internal void PonString (int posicion, string cadena) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (this.inicio + primero + 2 * cadena.Length - 1 >= this.longitud, "'posicion' inválida.");
            #endif
            //
            for (int indice = 0; indice < cadena.Length; ++indice) {
                char caracter = cadena [indice];
                this.almacen [primero + 2 * indice] = (byte) (caracter >> 8);
                this.almacen [primero + 2 * indice + 1] = (byte) (caracter);
            }
        }


        internal void TomaString (int posicion, int longitud_, StringBuilder cadena) {
            int primero = this.inicio + posicion;
            //
            #if DEBUG
            Depuracion.Valida (this.almacen == null, "'Buzon' vacío.");
            Depuracion.Valida (primero + 2 * longitud_ - 1 >= this.longitud, "'posicion' inválida.");
            Depuracion.Valida (cadena == null, "'cadena' nula");
            #endif
            //
            cadena.Length = 0;
            for (int indice = 0; indice < longitud_; ++indice) {
                char caracter =
                        (char) (((this.almacen [primero + 2 * indice    ] & 0xff) << 8) |
                                ((this.almacen [primero + 2 * indice + 1] & 0xff)     )  );
                cadena.Append (caracter);
            }
        }


    }


}
