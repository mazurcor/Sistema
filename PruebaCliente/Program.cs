using System;
using com.mazc.Sistema;


namespace PruebaCliente {


    class Program {


        static void Main (string [] args) {
            Console.Write ("CLIENTE\n\n");

            Conexion conexion = new Conexion ();
            try { 
                //mazc::Buzon clave;
                //CargaClavePublica (clave);
                //conexion.AseguraCliente (clave);
                conexion.IniciaCliente ("192.168.1.78", /*"localhost",*/ 27015);
                // 
                conexion.AgregaInteger (-123);
                conexion.AgregaInteger (-12345);
                conexion.AgregaString ("¡Hola tíos!");
                conexion.AgregaInteger (-321);
                conexion.AgregaInteger (-54321);
                conexion.AgregaString ("Adiós");
                conexion.EnviaPaquete ();
                //
//int r;
//std::cin >> r;

//                int i = conexion.RecibeInteger ();

                //
                string s;
                s = "primer envio";
                conexion.EnviaString (s);
                //
                s = conexion.RecibeString ();
                Console.Write ("1) " + s + "\n"); 
                //
                s = "segundo envio";
                conexion.EnviaString (s);
                //
                s = conexion.RecibeString ();
                Console.Write ("2) " + s + "\n");
                //
                s = "tercer envio";
                conexion.EnviaString (s);
                //
                s = conexion.RecibeString ();
                Console.Write ("3) " + s + "\n");
            } catch (ErrorConexion error) {
    		    Console.Write ("ErrorConexion: ");
	    	    Console.Write (error.Message);
                Console.Write ("\n");
            } finally { 
                conexion.Termina ();
            }
            //clave.Libera ();

            Console.Write ("Vale.\n");
            Console.ReadLine ();
        }


    }


}
