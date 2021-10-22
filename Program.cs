using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RLKTExecutableValidator
{
    class Program
    {

        class ExecutableValidator
        {
            static int ReservedSize = 48+4;
            static UInt32 Header = 0x47655267; // gReG

            public enum State
            { 
                HEADER_MISSMATCH,
                HASH_MISSMATCH,
                ALLES_OK,
            };

            public static byte[] DoChecksum(byte[] data)
            {
                using (var algo = new SHA384Managed())
                {
                    return algo.ComputeHash(data);
                }
            }

            public static bool BinaryCompare(byte[] arr1, byte[] arr2)
            {
                if (arr1.Length != arr2.Length)
                    return false;

                for(int i=0;i<arr1.Length;i++)
                {
                    if (arr1[i] != arr2[i])
                        return false;
                }

                return true;
            }

            public State Validate()
            {
                string filename = AppDomain.CurrentDomain.FriendlyName;

                FileStream file = File.OpenRead(filename);
                file.Seek(-ReservedSize, SeekOrigin.End);

                using (BinaryReader reader = new BinaryReader(file))
                {
                    //Check header
                    UInt32 header = reader.ReadUInt32();
                    if (header != Header)
                        return State.HEADER_MISSMATCH;

                    //Check hash
                    byte[] hash = reader.ReadBytes(48);
                    reader.BaseStream.Seek(0, SeekOrigin.Begin);
                    byte[] bytes = reader.ReadBytes((int)reader.BaseStream.Length - ReservedSize);
                    if (!BinaryCompare(hash, DoChecksum(bytes)))
                        return State.HASH_MISSMATCH;
                }

                //No error, all ok!
                return State.ALLES_OK;
            }
        
        }


        static void Main(string[] args)
        {
            ExecutableValidator validator = new ExecutableValidator();
            ExecutableValidator.State ValidState = validator.Validate();
            Console.WriteLine(ValidState.ToString());

            if(ValidState == ExecutableValidator.State.ALLES_OK)
            { 
                Console.WriteLine("Checksum passed!");
            } 
            else
            {
                Console.WriteLine("Failed, file modification detected.");
            }
        }
    }
}
