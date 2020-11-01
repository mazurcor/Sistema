using com.mazc.Sistema;
using System;


namespace CreaClavesRSA {


    class Program {


        static void Main (string [] args) {
            byte [] clave_publica;
            byte [] clave_privada;
            CifradoRSA.GeneraParClaves (out clave_publica, out clave_privada);
            //
            ImprimeCarga ("clave_publica", clave_publica);
            ImprimeCarga ("clave_privada", clave_privada);
        }


    static void ImprimeCarga (string variable, byte [] clave) {
        Console.Write ("\n");
        Console.Write ("        byte [] {0} = new byte [] {{", variable);
        for (int indice = 0; indice < clave.Length; ++ indice) {
            if (indice % 10 == 0) {
                
                Console.Write ("\n");
                Console.Write ("                ");
            }
//            Console.Write ("    {0} [{1,4}] = 0x{2:X2};\n", variable, indice, clave [indice]);
            Console.Write ("0x{0:X2}", clave [indice]);
            if (indice < clave.Length - 1) {
                Console.Write (", ");
            } else {
                Console.Write (" };\n");
            }
        }
        Console.Write ("\n");
    }


    }


}
