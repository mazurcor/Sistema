﻿using System;
using com.mazc.Sistema;


namespace PruebaCliente {


    class Program {


        static byte [] clave_publica = new byte [] {
                0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xDB,
                0xCF, 0x1E, 0x8D, 0xCB, 0xDE, 0x16, 0xE7, 0xFC, 0xD4, 0xF5,
                0x18, 0xBE, 0xC0, 0xB5, 0x75, 0xA2, 0xDF, 0x0C, 0xFC, 0x30,
                0x86, 0x7B, 0x28, 0x6D, 0xAA, 0x99, 0x1D, 0x37, 0xF7, 0x2C,
                0x75, 0x6C, 0xA7, 0x23, 0xAD, 0x70, 0x6F, 0x1C, 0x59, 0x03,
                0xDD, 0x80, 0x3A, 0xF7, 0x3C, 0xFD, 0x51, 0xC8, 0x4A, 0x8E,
                0x41, 0x7A, 0xAF, 0xC0, 0x60, 0xA6, 0xD4, 0x53, 0x50, 0x86,
                0x3F, 0x83, 0xE1, 0xFA, 0xA2, 0x4C, 0xC8, 0x21, 0x65, 0x7A,
                0xB3, 0xAE, 0x03, 0xBF, 0x83, 0x8E, 0xCA, 0x6C, 0xF1, 0x71,
                0x8B, 0x72, 0x9E, 0xC7, 0x82, 0x2F, 0xD8, 0x00, 0xDF, 0xDB,
                0x5C, 0xFE, 0x62, 0xCF, 0xBA, 0x5F, 0xA4, 0x87, 0x3E, 0x0D,
                0xCE, 0x14, 0xFE, 0xEC, 0xB1, 0xB8, 0x8F, 0x98, 0x6B, 0xB0,
                0xBC, 0x18, 0x3C, 0xE2, 0x98, 0x7D, 0xC4, 0x73, 0x1C, 0x79,
                0x52, 0xAE, 0x14, 0x4F, 0x15, 0x1F, 0x53, 0xAB, 0xE4, 0xEC,
                0x65, 0x4D, 0x0F, 0x2C, 0xB3, 0x8C, 0x12, 0x5B, 0x3E, 0x08,
                0xCF, 0x28, 0x0A, 0x62, 0x17, 0xF9, 0x2A, 0xED, 0xD5, 0xFF,
                0xFE, 0x7B, 0xD1, 0x52, 0xAB, 0xA3, 0xD2, 0xD9, 0xCC, 0x42,
                0x99, 0x26, 0x52, 0x6C, 0xA6, 0xDA, 0x47, 0xF8, 0xF0, 0x8A,
                0xA1, 0xCD, 0x7A, 0x98, 0x20, 0xEA, 0xE1, 0x92, 0x56, 0x95,
                0xD2, 0xA1, 0x9E, 0xC8, 0xD1, 0x8C, 0xCD, 0x51, 0x47, 0x78,
                0x7B, 0x0F, 0x8C, 0x7A, 0x8B, 0xC6, 0x8A, 0xD2, 0xF3, 0x1B,
                0x5F, 0xE0, 0x35, 0x9F, 0x01, 0x6B, 0x03, 0x7B, 0x7F, 0x48,
                0x19, 0xE7, 0x07, 0x44, 0x69, 0x4E, 0xC1, 0xF7, 0x53, 0xCC,
                0x80, 0xB6, 0x3B, 0xB8, 0x8D, 0x63, 0x02, 0x8D, 0x88, 0x59,
                0x91, 0x76, 0x58, 0x7C, 0xCA, 0x02, 0x9F, 0x99, 0x1C, 0x32,
                0xCD, 0x42, 0xC6, 0x64, 0x63, 0x2E, 0x70, 0xBF, 0xC2, 0x35,
                0x5E, 0xBF, 0x3F, 0x49, 0xB5, 0x02, 0x03, 0x01, 0x00, 0x01 };


        static void Main (string [] args) {
            Console.Write ("CLIENTE\n\n");

            Conexion conexion = new Conexion ();
            try { 
                conexion.AseguraCliente (clave_publica);
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
    		    Console.WriteLine ("ErrorConexion: ");
	    	    Console.WriteLine (error.Message);
            } catch (Exception error) {
    		    Console.WriteLine ("Excepción: ");
	    	    Console.WriteLine (error.Message);
                Console.WriteLine (error.StackTrace);
            } finally { 
                conexion.Termina ();
            }

            Console.Write ("Vale.\n");
            Console.ReadLine ();
        }


    }


}
