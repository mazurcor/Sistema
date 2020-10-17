﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;


namespace com.mazc.Sistema {


    /// <summary>
    /// Excepcion producidad por una instancia de 'Conexión' para indicar que se ha producido un 
    /// error durante en comunicación con en el programa remoto.
    /// </summary>
    /// <remarks>
    /// El error puede producirse en la red, en el sistema. También puede ser un error de validación 
    /// de tipo de los datos trasmitidos.
    /// </remarks>
    public class ErrorConexion : Exception {


        public ErrorConexion (string mensaje) :
            base (mensaje) {
        }


    }



    /// <summary>
    /// Excepcion producidad por una instancia de 'Conexión' para indicar que se ha terminado la
    /// conexión en el programa remoto.
    /// </summary>
    public class ConexionInterrumpida : Exception {


        public ConexionInterrumpida () :
            base () {
        }


    }



    /// <summary>
    /// Establece una conexión de red entre dos programas e intercambia datos entre ellos. 
    /// </summary>
    /// <remarks>
    /// El modelo de la conexión es cliente-servidor. El programa servidor crea una instancia de 
    /// 'Conexion' y permanece a la espera. Cuando el programa cliente crea una instancia de 
    /// 'Conexion' y la conecta con el servidor, el servidor crea otra instancia de 'Conexion', 
    /// llamada conexión de servicio. La conexión del cliente y la de servicio serán las que 
    /// intercambien los datos. El programa servidor puede atender a mas de un programa cliente, 
    /// pero entonces, debe ser multi-hilo.
    /// <para/>
    /// Usa la infraestructura de TCP/IP estandar del sistema. El programa servidor se configura 
    /// para usar un puerto TCP; el programa cliente indica la dirección IP y el puerto TCP del
    /// servidor.
    /// <para/>
    /// El protocolo de intercambio de datos debe seguir el modelo pregunta/respuesta. El servidor 
    /// permanece en espera de una pregunta. Cuando es necesario, el cliente prepara una pregunta y 
    /// la envía. Entonces, el servidor procesa la pregunta, prepara la respuesta y la envia. El 
    /// protocolo establece si la pregunta comprende varios envios (si son muchos datos) y si la 
    /// respuesta comprende cero, uno o más envíos (si son muchos datos).
    /// <para/>
    /// Es posible enviar y recibir datos individuales (numeros, cadenas de caracteres, ...), o 
    /// bien, paquetes formados por varios datos individuales. En ambos casos, 'Conexion' agrega 
    /// marcas de tipo y de longitud para garantiazar el cumplimiento del protocolo.
    /// <para/>
    /// La conexión se puede transformar en un canal seguro. Para ello se usan los métodos 
    /// 'AseguraCliente' y 'AseguraServidor'. El canal seguro usa técnicas criptograficas para 
    /// asegurar la confidencialidad y la autenticidad de la comunicación.
    /// </remarks>
    public class Conexion {


        #region constantes privadas
                                         
        private const byte marca_bool    = 70;
        private const byte marca_long    = 71;
        private const byte marca_int     = 72;
        private const byte marca_short   = 73;
        private const byte marca_byte    = 74;
        private const byte marca_string  = 75;
        private const byte marca_paquete = 81;
                
        private const int cabecera_paquete = 5;

        #endregion


        #region  variables privadas
                                         
        private bool iniciada;
        private bool de_servidor; 
		private bool de_servicio;
		private bool de_cliente;
        private bool erronea;
        private bool cerrada;

        private Seguridad seguridad;

        private Socket socket;

        // si seguridad es nulo, se usan estos buzones
        // en caso contrario, se usan los buzones de seguridad
        private Buzon buzon_paquete;
        // buzon_mensaje es un fragmento de buzon_paquete
        private Buzon buzon_mensaje;
    
        private bool paquete_entrada;
        private bool paquete_salida;

        private int longitud_paquete;
        private int posicion_paquete;

        private StringBuilder fabrica_cadena;

        #endregion


        /// <summary>
        /// Establece que la instancia se comunicará usando el canal seguro y asigna la clave 
        /// privada del cifrado 'RSA' usada por el canal seguro. 
        /// </summary>
        /// <remarks>
        /// La instancia de cliente que se comunique con esta también deberá usar el canal seguro. 
        /// El programa cliente debe usar la clave publica correspondiente a la clave privada 
        /// indicada.
        /// <para/>
        /// La llamada se debe hacer en una conexión no iniciada. Cuando se inicie la conexión, debe 
        /// ser de servidor. Es decir, se debe hacer con 'IniciaServidor'.
        /// </remarks>
        /// <param name="clave_privada">clave privada del cifrado 'RSA' usada por el canal seguro
        /// </param>
        public void AseguraServidor (byte [] clave_privada) {
            Depuracion.Valida (iniciada, "Conexión iniciada.");
            Depuracion.Valida (seguridad != null, "Conexión ya asegurada.");
            //
            seguridad = new Seguridad ();
            seguridad.ActivaDeServidor (clave_privada);
        }


        /// <summary>
        /// Establece que la instancia se comunicará usando el canal seguro y asigna la clave 
        /// pública del cifrado 'RSA' usada por el canal seguro. 
        /// </summary>
        /// <remarks>
        /// La instancia de servidor que se comunique con esta también deberá usar el canal seguro. 
        /// El programa servidor debe usar la clave privada correspondiente a la clave publica  
        /// indicada.
        /// <para/>
        /// La llamada se debe hacer en una conexión no iniciada. Cuando se inicie la conexión, debe 
        /// ser de cliente. Es decir, se debe hacer con 'IniciaCliente'.
        /// </remarks>
        /// <param name="clave_privada">clave pública del cifrado 'RSA' usada por el canal seguro
        /// </param>
        public void AseguraCliente (byte [] clave_publica) {
            Depuracion.Valida (iniciada, "Conexión iniciada.");
            Depuracion.Valida (seguridad != null, "Conexión ya asegurada.");
            //
            seguridad = new Seguridad ();
            seguridad.ActivaDeCliente (clave_publica);
        }


        /// <summary>
        /// Prepara la instancia para actuar como servidor de la conexión, la cual se realizará 
        /// mediante 'AceptaCliente'.
        /// </summary>
        /// <remarks>
        /// La conexión usa el puerto TCP que se indica en el parámetro. El puerto debe ser superior 
        /// a 1024.
        /// <param/>
        /// Tras la llamada, la conexión se considera iniciada y se considera 'de servidor'. Una vez 
        /// iniciada, se debe terminar mediante 'Termina', incluso cuando se producen excepciones en 
        /// la comunicación.
        /// </remarks>
        /// <param name="servicio">Número del puerto TCP usado por la conexión.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. Es este caso la 
        /// conexión no estará iniciada.</exception>
        public void IniciaServidor (int servicio) {
            Depuracion.Valida (iniciada, "Conexión iniciada.");
            Depuracion.Valida (1024 >= servicio || servicio > IPEndPoint.MaxPort, "servicio inválido: '" + servicio + "'");
            if (seguridad != null) {
                Depuracion.Valida (! seguridad.DeServidor, "Seguridad mal establecida.");
            }
            //
            try {
                IPEndPoint punto_final = new IPEndPoint (IPAddress.Any, servicio);
                socket = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Bind (punto_final);
                socket.Listen (int.MaxValue);
            } catch (SocketException excpn) {
                if (socket != null) {
                    socket.Dispose ();
                }
                throw new ErrorConexion (excpn.Message);
            }
            iniciada    = true;
            de_servidor = true;
            erronea     = false;
            cerrada     = false;
        }


        /// <summary>
        /// Responde a la conexión desde un cliente creando una instancia nueva de 'Conexion', que se 
        /// usará para realizar la comunicación.
        /// </summary>
        /// <remarks>
        /// Tras la llamada, la conexión nueva se considera iniciada y se considera 'de servicio'. 
        /// Como todas las conexiones iniciadas, se debe terminar mediante 'Termina', incluso cuando 
        /// se producen excepciones en la comunicación.
        /// </remarks>
        /// <returns>Instancia nueva de 'Conexion' que se comunicará con el cliente.</returns>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public Conexion AceptaCliente () {
            Depuracion.Valida (! iniciada, "Conexión no iniciada.");
            Depuracion.Valida (! de_servidor, "No es conexión de servidor");
            //
            Conexion conexion = new Conexion ();
            try {
                conexion.socket = socket.Accept ();
            } catch (SocketException excpn) {
                throw new ErrorConexion (excpn.Message);
            }
            conexion.iniciada    = true;
            conexion.de_servicio = true;
            conexion.erronea     = false;
            conexion.cerrada     = false;
            //
            if (seguridad != null) {
                conexion.seguridad = new Seguridad ();
                conexion.seguridad.ActivaDeServicio (seguridad);
            }
            //
            return conexion;
        }


        /// <summary>
        /// Prepara la instancia para actuar como cliente de la conexión.
        /// </summary>
        /// <remarks>
        /// La conexión usa la dirección IP del servidor y el puerto TCP del servidor que se indican 
        /// en los parámetros. El puerto debe el mismo especificado en 'IniciaServidor'.
        /// <param/>
        /// Tras la llamada, la conexión se considera iniciada y se considera 'de cliente'. Una vez 
        /// iniciada, se debe terminar mediante 'Termina', incluso cuando se producen excepciones en 
        /// la comunicación.
        /// </remarks>
        /// <param name="servidor">Dirección IP o nombre DNS del servidor.</param>
        /// <param name="servicio">Número del puerto TCP del servidor.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. Es este caso la 
        /// conexión no estará iniciada.</exception>
        public void IniciaCliente (string servidor, int servicio) {
            Depuracion.Valida (iniciada, "Conexión iniciada.");
            Depuracion.Valida (servidor == null || servidor.Length <= 0, "servidor inválido: '" + servidor + "'");
            if (seguridad != null) {
                Depuracion.Valida (! seguridad.DeCliente, "Seguridad mal establecida.");
            }
            Depuracion.Valida (1024 >= servicio || servicio > IPEndPoint.MaxPort, "servicio inválido: '" + servicio + "'");
            //
            try {
                //IPHostEntry ip_servidor = Dns.GetHostEntry (servidor);
                IPAddress [] direcciones = Dns.GetHostAddresses (servidor);
                IPEndPoint punto_final = new IPEndPoint (direcciones [0], servicio);
                socket = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Connect (punto_final);
            } catch (SocketException excpn) {
                if (socket != null) {
                    socket.Dispose ();
                }
                throw new ErrorConexion (excpn.Message);
            }
            iniciada   = true;
            de_cliente = true;
            erronea    = false;
            cerrada    = false;
        }


        /// <summary>
        /// Termina una conexíon liberando los recursos de red usados.
        /// </summary>
        /// <remarks>
        /// Se deben terminar las conexiones iniciadas, sean de servidor, servicio o cliente, se 
        /// hayan producido errores o no. Si la conexión no estaba iniciada no actua. Tras la 
        /// llamada, la conexión deja de estar iniciada.
        /// <para/>
        /// No puede haber un paquete en preparación no enviado, ni un paquete recibido no 
        /// consumido.
        /// <para/>
        /// Si el cliente termina la conexión y el servidor continua realizando recepciones, usando
        /// un método 'Recibe...', este lanza la excepción 'ConexionInterrumpida'.
        /// </remarks>
        public void Termina () {
            if (! iniciada) {
                return;
            }
            //
            Depuracion.Valida (paquete_entrada, "Paquete de entrada no consumido");
            Depuracion.Valida (paquete_salida,  "Paquete de salida no consumido");
            //
	        if (de_cliente) {
                //
                if (! erronea && ! cerrada) {  
                    //
                    try {
                        socket.Shutdown (SocketShutdown.Both);
                    } catch (SocketException excpn) {
                        throw new ErrorConexion (excpn.Message);
                    }
                }
                //
            } else if (de_servicio) {
                //
                // si al enviar o recibir la comunicación ha fallado, no hay que insistir
                // además, si se cancela el servidor (a proposito) se bloquea en el 'recv'
                //
	        } else if (de_servidor) {
                //
                // la conexión de servidor nunca conecta el socket, por tanto, no se puede hacer 'shutdown'
		        //
	        }
            //
            socket.Close ();
            socket.Dispose ();
            //
            if (seguridad == null) {
                if (buzon_paquete.Longitud > 0) {
                    buzon_mensaje.AnulaFragmento (ref buzon_paquete);
                    buzon_mensaje.Libera ();
                }
            }
            //
            iniciada = false;            
        }


        /// <summary>
        /// Envia un número entero largo (64 bits) al programa remoto.
        /// </summary>
        /// <remarks>
        /// Envía también una marca de validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaLongInt (long numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (9);
            buzon_paquete [0] = marca_long;
            buzon_paquete.PonLong (1, numero);
            EnviaConexion (9);
        }          


        /// <summary>
        /// Recibe un número entero largo (64 bits) del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son del tipo correcto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número recibido.</returns>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public long RecibeLongInt () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (9);
            RecibeConexion (0, 9);
            if (buzon_paquete [0] != marca_long) {
                throw new ErrorConexion ("Fallo en recepción de entero largo");
            }
            return buzon_paquete.TomaLong (1);
        }              


        /// <summary>
        /// Envia un número entero al programa remoto.
        /// </summary>
        /// <remarks>
        /// Envía también una marca de validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaInteger (int numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (5);
            buzon_paquete [0] = marca_int;
            buzon_paquete.PonInt (1, numero);
            EnviaConexion (5);
        }          


        /// <summary>
        /// Recibe un número entero del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son del tipo correcto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número recibido.</returns>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public int RecibeInteger () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (5);
            RecibeConexion (0, 5);
            if (buzon_paquete [0] != marca_int) {
                throw new ErrorConexion ("Fallo en recepción de entero");
            }
            return buzon_paquete.TomaInt (1);
        }              


        /// <summary>
        /// Envia un número entero corto (16 bits) al programa remoto.
        /// </summary>
        /// <remarks>
        /// Envía también una marca de validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaShortInt (short numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (3);
            buzon_paquete [0] = marca_short;
            buzon_paquete.PonShort (1, numero);
            EnviaConexion (3);
        }          


        /// <summary>
        /// Recibe un número entero corto (16 bits) del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son del tipo correcto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número recibido.</returns>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public short RecibeShortInt () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (3);
            RecibeConexion (0, 3);
            if (buzon_paquete [0] != marca_short) {
                throw new ErrorConexion ("Fallo en recepción de entero corto");
            }
            return buzon_paquete.TomaShort (1);
        }              


        /// <summary>
        /// Envia un byte (sin signo) al programa remoto.
        /// </summary>
        /// <remarks>
        /// Envía también una marca de validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaByte (byte numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (2);        
            buzon_paquete [0] = marca_byte;
            buzon_paquete.PonByte (1, numero);
            EnviaConexion (2);
        }          


        /// <summary>
        /// Recibe un byte del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son del tipo correcto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número recibido.</returns>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public byte RecibeByte () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (2);
            RecibeConexion (0, 2);
            if (buzon_paquete [0] != marca_byte) {
                throw new ErrorConexion ("Fallo en recepción de byte");
            }
            return buzon_paquete.TomaByte (1);
        }              


        /// <summary>
        /// Envia una cadena de caracteres al programa remoto.
        /// </summary>
        /// <remarks>
        /// Envía también una marca de validación de tipo y la longitud de la cadena. Si la cadena 
        /// es nula, envia la cadena vacía.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// </remarks>
        /// <param name="numero">Cadena de caracteres a enviar.</param>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaString (String cadena) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            if (cadena == null) {
                cadena = "";
            }
            int longitud = cadena.Length * 2;
            PreparaBuzones (5 + longitud);
            buzon_paquete [0] = marca_string;
            buzon_paquete.PonInt (1, longitud);
            buzon_paquete.PonString (5, cadena);
            EnviaConexion (5 + longitud);
        }          


        /// <summary>
        /// Recibe una cadena de caracteres del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son del tipo correcto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Cadena de caracteres recibido.</returns>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public String RecibeString () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (5);
            RecibeConexion (0, 5);
            if (buzon_paquete [0] != marca_string) {
                throw new ErrorConexion ("Fallo en recepción de cadena");
            }
            int longitud = buzon_paquete.TomaInt (1);
            if (longitud < 0) {
                throw new ErrorConexion ("Fallo en recepción de longitud de cadena");
            }
            if (longitud % 2 != 0) {
                throw new ErrorConexion ("Fallo en recepción de longitud de cadena");
            }
            if (longitud == 0) {
                return "";
            }
            PreparaBuzones (5 + longitud);
            RecibeConexion (5, longitud);
            return TomaStringBuzon (5, longitud / 2);
        }              


        /// <summary>
        /// Agrega un valor booleano al paquete de salida que se va a enviar.
        /// </summary>
        /// <remarks>
        /// Si no estaba establecido, se establece el paquete de salida. Agrega también una marca de 
        /// validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <param name="numero">Valor booleano a enviar.</param>
        public void AgregaBoolean (bool valor) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            //
            if (! paquete_salida) {
                paquete_salida = true;
                longitud_paquete = cabecera_paquete;
                posicion_paquete = cabecera_paquete;
            }
            PreparaBuzones (longitud_paquete + 2);
            buzon_paquete [posicion_paquete] = marca_bool;
            byte marca = 0;
            if (valor) {
                marca = 1;
            }
            buzon_paquete.PonByte (posicion_paquete + 1, marca);
            longitud_paquete += 2;
            posicion_paquete += 2;
        }          


        /// <summary>
        /// Agrega un número entero largo (64 bits) al paquete de salida que se va a enviar.
        /// </summary>
        /// <remarks>
        /// Si no estaba establecido, se establece el paquete de salida. Agrega también una marca de 
        /// validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        public void AgregaLongInt (long numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            //
            if (! paquete_salida) {
                paquete_salida = true;
                longitud_paquete = cabecera_paquete;
                posicion_paquete = cabecera_paquete;
            }
            PreparaBuzones (longitud_paquete + 9);
            buzon_paquete [posicion_paquete] = marca_long;
            buzon_paquete.PonLong (posicion_paquete + 1, numero);
            longitud_paquete += 9;
            posicion_paquete += 9;
        }          


        /// <summary>
        /// Agrega un número entero al paquete de salida que se va a enviar.
        /// </summary>
        /// <remarks>
        /// Si no estaba establecido, se establece el paquete de salida. Agrega también una marca de 
        /// validación de tipo.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <param name="numero">Número a enviar.</param>
        public void AgregaInteger (int numero) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            //
            if (! paquete_salida) {
                paquete_salida = true;
                longitud_paquete = cabecera_paquete;
                posicion_paquete = cabecera_paquete;
            }
            PreparaBuzones (longitud_paquete + 5);
            buzon_paquete [posicion_paquete] = marca_int;
            buzon_paquete.PonInt (posicion_paquete + 1, numero);
            longitud_paquete += 5;
            posicion_paquete += 5;
        }          


        /// <summary>
        /// Agrega una cadena de caracteres al paquete de salida que se va a enviar.
        /// </summary>
        /// <remarks>
        /// Si no estaba establecido, se establece el paquete de salida. Agrega también una marca de 
        /// validación de tipo y la longitud de la cadena.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <param name="numero">Cadena de caracteres a enviar.</param>
        public void AgregaString (String cadena) {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            //
            if (cadena == null) {
                cadena = "";
            }
            if (! paquete_salida) {
                paquete_salida = true;
                longitud_paquete = cabecera_paquete;
                posicion_paquete = cabecera_paquete;
            }
            int longitud = cadena.Length * 2;
            PreparaBuzones (longitud_paquete + 5 + longitud);
            buzon_paquete [posicion_paquete] = marca_string;
            buzon_paquete.PonInt (posicion_paquete + 1, longitud);
            longitud_paquete += 5;
            posicion_paquete += 5;
            if (longitud > 0) {
                buzon_paquete.PonString (posicion_paquete, cadena);
                longitud_paquete += longitud;
                posicion_paquete += longitud;
            }
        }          


        /// <summary>
        /// Envia el paquete de datos, preparado previamente, al programa remoto.
        /// </summary>
        /// <remarks>
        /// El paquete debe haberse preparado mediante los métodos 'Agrega...·. Envía también una 
        /// marca de paquete y su longitud.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No pueden haber un 
        /// paquete recibido no consumido.
        /// </remarks>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red.</exception>
        public void EnviaPaquete () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (! paquete_salida, "Paquete no preparado.");
            //
            buzon_paquete [0] = marca_paquete;
            buzon_paquete.PonInt (1, longitud_paquete);
            try {
                EnviaConexion (longitud_paquete);
            } finally {
                paquete_salida = false;
            }
        }          


        /// <summary>
        /// Recibe un paquete de datos del programa remoto.
        /// </summary>
        /// <remarks>
        /// Si no hay datos a recibir, permanece en espera. Se desbloquea cuando el programa remoto
        /// envia datos o termina la conexión (de cliente).
        /// <para/>
        /// Valida que los datos recibidos son un paquete de datos. A continuación, los datos del 
        /// paquete se obtienen mediante los métodos 'Extrae...', en el mismo orden en el que los 
        /// agregó el programa remoto.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado, ni un paquete recibido no consumido.
        /// <para/>
        /// <exception cref="ConexionInterrumpida">El programa remoto es de cliente y ha terminado la 
        /// conexión.</exception>
        /// <exception cref="ErrorConexion">Si se ha producido un error en la red. O bién, los datos 
        /// recibidos no son del tipo correcto.</exception>
        public void RecibePaquete () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (cerrada, "Conexión cerrada.");
            Depuracion.Valida (erronea, "Conexión erronea.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (paquete_entrada, "Paquete recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            PreparaBuzones (5);
            RecibeConexion (0, 5);
            if (buzon_paquete [0] != marca_paquete) {
                throw new ErrorConexion ("Fallo en paquete recibido");
            }
            longitud_paquete = buzon_paquete.TomaInt (1);
            if (longitud_paquete <= cabecera_paquete) {
                throw new ErrorConexion ("Fallo en longitud de paquete recibido");
            }
            PreparaBuzones (longitud_paquete);
            posicion_paquete = cabecera_paquete;
            RecibeConexion (posicion_paquete, longitud_paquete - cabecera_paquete);
            paquete_entrada = true;
        }              

    
        /// <summary>
        /// Extrae un número valor booleano del paquete recibido.
        /// </summary>
        /// <remarks>
        /// Valida que los datos a extraer son del tipo correcto. Cuando no quedan más datos a 
        /// extraer, el paquete queda consumido.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado. Y debe haber un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Valor booleano extraido.</returns>
        /// <exception cref="ErrorConexion">Los datos extraidos no son del tipo correcto.
        /// </exception>
        public bool ExtraeBoolean () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (! paquete_entrada, "Paquete no recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            if (longitud_paquete - posicion_paquete < 2) {
                paquete_entrada = false;
                throw new ErrorConexion ("Paquete recibido incompleto");
            }
            if (buzon_paquete [posicion_paquete] != marca_bool) {
                paquete_entrada = false;
                throw new ErrorConexion ("booleano inválido en paquete recibido");
            }
            byte marca = buzon_paquete.TomaByte (posicion_paquete + 1);
            posicion_paquete += 2;
            if (posicion_paquete == longitud_paquete) {
                paquete_entrada = false;
            }
            return marca == 1;
        }                


        /// <summary>
        /// Extrae un número entero largo (64 bits) del paquete recibido.
        /// </summary>
        /// <remarks>
        /// Valida que los datos a extraer son del tipo correcto. Cuando no quedan más datos a 
        /// extraer, el paquete queda consumido.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado. Y debe haber un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número extraido.</returns>
        /// <exception cref="ErrorConexion">Los datos extraidos no son del tipo correcto.
        /// </exception>
        public long ExtraeLongInt () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (! paquete_entrada, "Paquete no recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            if (longitud_paquete - posicion_paquete < 9) {
                paquete_entrada = false;
                throw new ErrorConexion ("Paquete recibido incompleto");
            }
            if (buzon_paquete [posicion_paquete] != marca_long) {
                paquete_entrada = false;
                throw new ErrorConexion ("Entero inválido en paquete recibido");
            }
            long numero = buzon_paquete.TomaLong (posicion_paquete + 1);
            posicion_paquete += 9;
            if (posicion_paquete == longitud_paquete) {
                paquete_entrada = false;
            }
            return numero;
        }                


        /// <summary>
        /// Extrae un número entero del paquete recibido.
        /// </summary>
        /// <remarks>
        /// Valida que los datos a extraer son del tipo correcto. Cuando no quedan más datos a 
        /// extraer, el paquete queda consumido.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado. Y debe haber un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Número extraido.</returns>
        /// <exception cref="ErrorConexion">Los datos extraidos no son del tipo correcto.
        /// </exception>
        public int ExtraeInteger () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (! paquete_entrada, "Paquete no recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            if (longitud_paquete - posicion_paquete < 5) {
                paquete_entrada = false;
                throw new ErrorConexion ("Paquete recibido incompleto");
            }
            if (buzon_paquete [posicion_paquete] != marca_int) {
                paquete_entrada = false;
                throw new ErrorConexion ("Entero inválido en paquete recibido");
            }
            int numero = buzon_paquete.TomaInt (posicion_paquete + 1);
            posicion_paquete += 5;
            if (posicion_paquete == longitud_paquete) {
                paquete_entrada = false;
            }
            return numero;
        }                


        /// <summary>
        /// Extrae una cadena de caracteres del paquete recibido.
        /// </summary>
        /// <remarks>
        /// Valida que los datos a extraer son del tipo correcto. Cuando no quedan más datos a 
        /// extraer, el paquete queda consumido.
        /// <para/>
        /// La conexión debe estar iniciada y ser de cliente o de servicio. No puede haber un 
        /// paquete en preparación no enviado. Y debe haber un paquete recibido no consumido.
        /// consumido.
        /// </remarks>
        /// <returns>Cadena de caracteres extraida.</returns>
        /// <exception cref="ErrorConexion">Los datos extraidos no son del tipo correcto.
        /// </exception>
        public String ExtraeString () {
            Depuracion.Valida (! iniciada, "Conexión no  iniciada.");
            Depuracion.Valida (de_servidor, "Es conexión de servidor.");
            Depuracion.Valida (! paquete_entrada, "Paquete no recibido.");
            Depuracion.Valida (paquete_salida, "Paquete en preparación.");
            //
            if (longitud_paquete - posicion_paquete < 5) {
                paquete_entrada = false;
                throw new ErrorConexion ("Paquete recibido incompleto");
            }
            if (buzon_paquete [posicion_paquete] != marca_string) {
                paquete_entrada = false;
                throw new ErrorConexion ("Cadena inválida en paquete recibido");
            }
            int longitud = buzon_paquete.TomaInt (posicion_paquete + 1);
            posicion_paquete += 5;
            if (longitud < 0) {
                paquete_entrada = false;
                throw new ErrorConexion ("Longitud de cadena inválida en paquete recibido");
            }
            if (longitud % 2 != 0) {
                paquete_entrada = false;
                throw new ErrorConexion ("Longitud de cadena inválida en paquete recibido");
            }
            if (longitud == 0) {
                if (posicion_paquete == longitud_paquete) {
                    paquete_entrada = false;
                }
                return "";
            }
            if (longitud_paquete - posicion_paquete < longitud) {
                paquete_entrada = false;
                throw new ErrorConexion ("Paquete recibido inconsistente");
            }
            String cadena = TomaStringBuzon (posicion_paquete, longitud / 2);
            posicion_paquete += longitud;
            if (posicion_paquete == longitud_paquete) {
                paquete_entrada = false;
            }
            return cadena;
        }                


        #region métodos privados


        private void PreparaBuzones (int longitud) {
            // será	longitud > 0
            //
            if (seguridad != null) {
                seguridad.PreparaBuzones (longitud);
                return;
            }
            //
    	    if (buzon_paquete.Longitud == 0) {
                buzon_mensaje.Reserva (longitud);
                buzon_mensaje.CreaFragmento (0, longitud, ref buzon_paquete);
                return;
            }
            if (buzon_paquete.Longitud < longitud) {
                buzon_mensaje.AnulaFragmento (ref buzon_paquete);
                Buzon nuevo = new Buzon ();
                nuevo.Reserva (longitud);
                if (paquete_entrada || paquete_salida) {
                    Buzon.Copia (buzon_mensaje, ref nuevo, buzon_mensaje.Longitud);
                }
                buzon_mensaje.TrasponBuzon (ref nuevo);
                buzon_mensaje.CreaFragmento (0, longitud, ref buzon_paquete);
            }
        }
    

        private String TomaStringBuzon (int posicion, int longitud) {
            if (fabrica_cadena == null) {
                fabrica_cadena = new StringBuilder ();
            } else {
                fabrica_cadena.Length = 0;
            }
            buzon_paquete.TomaString (posicion, longitud, fabrica_cadena);
            return fabrica_cadena.ToString ();
        }
    
    
        // throws ErrorConexion 
        private void EnviaConexion (int longitud) {
            if (seguridad != null) {
                seguridad.Envia ();
                return;
            }
		    EnviaSocket (buzon_mensaje, longitud);
        }      


        // throws ErrorConexion, ConexionInterrumpida 
        private void RecibeConexion (int posicion, int longitud) {
            // 'Conexion' hace dos llamadas a este método, la primera para recibir la cabecera del 
            // mensaje, que incluye su longitud, y la segunda para obtener el resto del mensaje. La 
            // primera llamada se hace con 'posicion' igual a cero, y la segunda distinto de cero.
            // 'Seguridad' encapsula el mensaje en su propio formato y debe desencriptar el mensaje 
            // completo. Por eso recibe el mensaje completo en la primera llamada, con 'posicion' igual 
            // a cero, e ignora la segunda llamada y además de ignora 'longitud'.
            if (seguridad != null) {
                if (posicion == 0) {
                    seguridad.Recibe ();
                }
                return;
            }
		    RecibeSocket (buzon_mensaje, posicion, longitud);
        }      


        private void EnviaSocket (in Buzon buzon, int longitud) {
            int posicion = buzon.Inicio;
            // puede ocurrir que no se envien de una vez todos los bytes pedidos
            while (true) {
                int enviados;
                try {
                    enviados = socket.Send (
                        buzon.Almacen, posicion, longitud, SocketFlags.None);
                } catch (SocketException excepcion) {
                    erronea = true;
                    throw new ErrorConexion (excepcion.Message);
                } catch (Exception excepcion) { 
                    Depuracion.Cancela (excepcion);
                    return;
                }
                if (enviados == longitud) {
                    break;
                }
                posicion += enviados;
                longitud -= enviados;
            }
        }


        private void RecibeSocket (in Buzon buzon, int posicion, int longitud) {
            posicion += buzon.Inicio;
            // puede ocurrir que no se reciban de una vez todos los bytes pedidos
            while (true) {
                int recibidos;
                try {
                    recibidos = socket.Receive (
                        buzon_paquete.Almacen, posicion, longitud, SocketFlags.None);
                } catch (SocketException excepcion) {
                    erronea = true;
                    throw new ErrorConexion (excepcion.Message);
                } catch (Exception excepcion) { 
                    Depuracion.Cancela (excepcion);
                    return;  
                }
                // si se reciben 0 bytes es porque el socket remoto ha realizado un 'Shutdown'
                if (recibidos == 0) {
                    if (de_cliente) {
                        erronea = true;
				        throw new ErrorConexion ("Conexión prematuramente cerrada por el servidor");
                    } else {
                        cerrada = true;
                        // el socket remoto es de cliente, el Shutdown no es un error, indica que el 
                        // cliente ha terminado la conexión abruptamente, sin notificarlo con un 
                        // mensaje, para informar se usa la excepción
				        throw new ConexionInterrumpida ();
                    }
                }
                if (recibidos == longitud) {
                    break;
                }
                posicion += recibidos;
                longitud -= recibidos;
            }
        }


        #endregion


    }


}