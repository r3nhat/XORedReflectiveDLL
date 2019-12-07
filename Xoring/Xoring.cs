using System;
using System.IO;
using System.Text;

namespace XoringNew
{
    public class XoringNew
    {
        //https://stackoverflow.com/questions/3710132/byte-array-cryptography-in-c-sharp

        public static byte[] XorEncrypt(byte[] shellcode, string key)
        {
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)(shellcode[i] ^ key[i % key.Length]);
            }

            return shellcode;
        }


        static void Main(string[] args)
        {
            // Change the key below
            string key = "This1sTheK3y";

            // Paste your Shellcode below
            byte[] shellcode = { 0xab, };
            byte[] Encryptedshellcode;

            Encryptedshellcode = XorEncrypt(shellcode, key);
            Console.WriteLine($"[+] -------------------");
            Console.WriteLine($"[+] Xoring Shellcode...");
            Console.WriteLine($"[+] -------------------");
            StringBuilder build = new StringBuilder();
            foreach (byte b in Encryptedshellcode)
            {
                build.Append(" 0x");
                build.AppendFormat("{0:X2}", b);

            }
            var XoredShellcode = build;
            for (int i = 5; i <= XoredShellcode.Length - 1; i += 5)
            {

                XoredShellcode = XoredShellcode.Insert(i, ",");
                i++;
            }

            Console.WriteLine($"[+] Shellcode Xored Successfully.");
            //Console.WriteLine($"[+] ==========================================");
            //Console.WriteLine(XoredShellcode.ToString());
            //Console.WriteLine($"[+] ==========================================");
            string datetime = DateTime.Now.ToString("yyyy-dd-M--HH-mm-ss");
            string path = Directory.GetCurrentDirectory();
            string filename = "xored_shellcode_" + datetime + ".txt";
            using (StreamWriter sw = new StreamWriter(filename, true))
            {
                sw.WriteLine(XoredShellcode.ToString());
                sw.Close();
            }
            Console.WriteLine($"[+] File {filename} created under: {path} directory!");
            Console.WriteLine();
        }
    }
}