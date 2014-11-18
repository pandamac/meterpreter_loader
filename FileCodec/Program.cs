using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FileCodec
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
                Console.WriteLine("FileCodec.exe [-d] password inputFile outputFile");
            else
            {
                if(args[0] == "-d")
                {
                    Shared.Encryptor.DecryptFile(args[1], args[2], args[3]);
                }
                else
                {
                    Shared.Encryptor.EncryptFile(args[0], args[1], args[2]);
                }
            }
        }
    }
}
