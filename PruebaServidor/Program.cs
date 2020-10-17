using System;
using com.mazc.Sistema;


namespace PruebaServidor {


    class Program {


        static void Main (string [] args) {
            Console.Write ("SERVIDOR\n\n");

            Conexion servidor = new Conexion ();
	        Conexion conexion = new Conexion ();
            try {
                //mazc::Buzon clave;
                //CargaClavePrivada (clave);
                //servidor.AseguraServidor (clave);
                servidor.IniciaServidor (27015);

                conexion = servidor.AceptaCliente ();
            
                conexion.RecibePaquete ();
    //int r;
    //std::cin >> r;
                int numero = conexion.ExtraeInteger ();
                Console.Write (numero + "\n");
                numero = conexion.ExtraeInteger ();
                Console.Write (numero + "\n");

                string cadena = conexion.ExtraeString ();
                Console.Write (cadena + "\n");

                numero = conexion.ExtraeInteger ();
                Console.Write (numero + "\n");
                numero = conexion.ExtraeInteger ();
                Console.Write (numero + "\n");
                    
                cadena = conexion.ExtraeString ();
                Console.Write (cadena + "\n");

    //            conexion.EnviaInteger (33);


                string s;
        
                s = conexion.RecibeString ();
                Console.Write ("1) " + s + "\n"); 

                s = "primera respuesta";
                conexion.EnviaString (s);

                s = conexion.RecibeString ();
                Console.Write ("2) " + s + "\n"); 

                s = "segunda respuesta";
                conexion.EnviaString (s);

                s = conexion.RecibeString ();
                Console.Write ("3) " + s + "\n"); 

                s = "tercera respuesta";
                conexion.EnviaString (s);

            } catch (ConexionInterrumpida) {
    		    Console.Write ("Conexión interrumpida. ");
                Console.Write ("\n");
            } catch (ErrorConexion error) {
    		    Console.Write ("ErrorConexion: ");
	    	    Console.Write (error.Message);
                Console.Write ("\n");
            } finally { 
                conexion.Termina ();
                servidor.Termina ();
            }


            //clave.Libera ();

            Console.Write ("Vale.\n");
            Console.ReadLine ();
        }


    }


}
