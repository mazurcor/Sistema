using com.mazc.Sistema;
using System;
using System.Text;

namespace CreaClavesRSA {


    class Program {


        static void Main (string [] args) {
#if DEBUG  
        Console.WriteLine("DEBUG is defined");  
#else  
        Console.WriteLine("DEBUG is not defined");  
#endif  
        }


    }


}
