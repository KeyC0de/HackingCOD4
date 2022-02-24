#include "winner.h"
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <psapi.h>
// Net Management - Users, Groups, etc.
#include <lm.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <dbghelp.h>
#include "utils.h"
#include "os_utils.h"
#include "assertions_console.h"
#include "system_info.h"

#pragma comment( lib, "netapi32.lib" )
#pragma comment( lib, "psapi.lib" )
#pragma comment( lib, "user32.lib" )
#pragma comment( linker, "/SUBSYSTEM:WINDOWS" )


void help()
{
	std::cout << "Make sure the requested resource is currently active!\n";
}


enum class Register : int
{
	eax = 1,
	ebx,
	ecx,
	edx,
	esi,
	edi
};

/*
void printFileVersion( TCHAR* szFilePath )
{
	DWORD               dwSize              = 0;
	BYTE                *pbVersionInfo      = nullptr;
	VS_FIXEDFILEINFO    *pFileInfo          = nullptr;
	UINT                puLenFileInfo       = 0;

	// Get the version information for the file requested
	dwSize = GetFileVersionInfoSizeW( szFilePath, nullptr );
	if ( dwSize == 0 )
	{
		printf( "Error in GetFileVersionInfoSize: %d\n", GetLastError() );
		return;
	}

	pbVersionInfo = new BYTE[ dwSize ];

	if ( !GetFileVersionInfoW( szFilePath, 0, dwSize, pbVersionInfo ) )
	{
		printf( "Error in GetFileVersionInfo: %d\n", GetLastError() );
		delete[] pbVersionInfo;
		return;
	}

	if ( !VerQueryValueW( pbVersionInfo, TEXT("\\"), (LPVOID*) &pFileInfo, &puLenFileInfo ) )
	{
		printf( "Error in VerQueryValue: %d\n", GetLastError() );
		delete[] pbVersionInfo;
		return;
	}

	// pFileInfo->dwFileVersionMS is usually zero. However, you should check
	// this if your version numbers seem to be wrong
	printf( "File Version: %d.%d.%d.%d\n",
		( pFileInfo->dwFileVersionLS >> 24 ) & 0xff,
		( pFileInfo->dwFileVersionLS >> 16 ) & 0xff,
		( pFileInfo->dwFileVersionLS >>  8 ) & 0xff,
		( pFileInfo->dwFileVersionLS >>  0 ) & 0xff
		);

	// pFileInfo->dwProductVersionMS is usually zero. However, you should check
	// this if your version numbers seem to be wrong.
	printf( "Product Version: %d.%d.%d.%d\n",
		( pFileInfo->dwProductVersionLS >> 24 ) & 0xff,
		( pFileInfo->dwProductVersionLS >> 16 ) & 0xff,
		( pFileInfo->dwProductVersionLS >>  8 ) & 0xff,
		( pFileInfo->dwProductVersionLS >>  0 ) & 0xff
		);
}*/

//===================================================
//	\function	enumerateInstalledPrograms
//	\brief  enumerate the registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
//				basically does what MsiEnumProductsEx does
//	\date	2021/09/20 20:06
bool enumerateInstalledPrograms()
{
	HKEY hUninstKey = nullptr;
	HKEY hAppKey = nullptr;
	WCHAR sAppKeyName[1024];
	WCHAR sSubKey[1024];
	WCHAR sDisplayName[1024];
	WCHAR sRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
	long lResult = ERROR_SUCCESS;
	DWORD dwType = KEY_ALL_ACCESS;
	DWORD dwBufferSize = 0;

	int ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE, sRoot, 0, KEY_READ, &hUninstKey );
	ASSERT_HRES_REGISTRY_IF_FAILED( ret );

	for ( DWORD dwIndex = 0; lResult == ERROR_SUCCESS; dwIndex++ )
	{
		// enumerate all sub keys...
		dwBufferSize = sizeof sAppKeyName;
		lResult = RegEnumKeyExW( hUninstKey,
			dwIndex,
			sAppKeyName,
			&dwBufferSize,
			nullptr,
			nullptr,
			nullptr,
			nullptr );
		if ( lResult == ERROR_SUCCESS )
		{
			// open the sub key
			wsprintfW( sSubKey,
				L"%s\\%s",
				sRoot,
				sAppKeyName );
			int ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE,
				sSubKey,
				0,
				KEY_READ,
				&hAppKey );
			if ( ret != ERROR_SUCCESS )
			{
				RegCloseKey( hAppKey );
				RegCloseKey( hUninstKey );
				return false;
			}

			//Get the display name value from the application's sub key.
			dwBufferSize = sizeof sDisplayName;

			ret = RegQueryValueExW( hAppKey,
				L"DisplayName",
				nullptr,
				&dwType,
				(unsigned char*)sDisplayName,
				&dwBufferSize );
			ASSERT_HRES_REGISTRY_IF_FAILED( ret );

			if ( ret == ERROR_SUCCESS )
			{
				wprintf( L"%s\n", sDisplayName );
			}
			else
			{
				// display name value does not exist, this application was probably uninstalled
			}

			RegCloseKey( hAppKey );
		}
	}

	RegCloseKey( hUninstKey );
	return true;
}

int netQueryInformation( int argc,
	char* argv[] )
{
	PNET_DISPLAY_GROUP pBuff, p;
	DWORD res, dwRec, i = 0;
	// pass nullptr to retrieve the local information.
	TCHAR szServer[255] = TEXT( "" );

	if ( argc > 1 )
	{
		// Check to see if a server name was passed - if so, convert it to Unicode.
		MultiByteToWideChar( CP_ACP,
			0,
			argv[1],
			-1,
			szServer,
			sizeof szServer );
	}
	do
	{ 
		// The NetQueryDisplayInformation function returns user account, computer, or group account information.
		//	Call this function to quickly enumerate account information for display in user interfaces.
		// 1 = user account information, 2 = computer information, 3 group account info
		res = NetQueryDisplayInformation( szServer,
			3,
			i,
			1000,
			MAX_PREFERRED_LENGTH,
			&dwRec,
			(PVOID*) &pBuff );

		// If the call succeeds
		if ( ( res == ERROR_SUCCESS ) || ( res == ERROR_MORE_DATA ) )
		{
			p = pBuff;
			for ( ; dwRec > 0; dwRec-- )
			{
				// Print the retrieved group information.
				printf( "Name:		%S\n"
						"Comment:	%S\n"
						"Group ID:  %u\n"
						"Attributes: %u\n"
						"--------------------------------\n",
						p->grpi3_name,
						p->grpi3_comment,
						p->grpi3_group_id,
						p->grpi3_attributes );

				// If there is more data, set the index.
				i = p->grpi3_next_index;
				p++;
			}
			// Free the allocated memory.
			NetApiBufferFree( pBuff );
		}
		else
		{
			printf( "Error: %u\n", res );
		}
	// Continue while there is more data.
	} while ( res == ERROR_MORE_DATA );

	return EXIT_SUCCESS;
}

// The NetUserEnum function only returns information to which the caller has Read access.
// The caller must have List Contents access to the Domain object, and Enumerate Entire SAM Domain access on the SAM Server object located in the System container.
// Security Account Manager (SAM) is a database that is present on Windows computers
//	that stores user accounts and security descriptors for users on the local computer
// The NetUserEnum function does not support a level parameter of 4 and the USER_INFO_4 structure.
// Instead NetUserGetInfo function supports a level parameter of 4 and the USER_INFO_4 structure.
#pragma warning( disable : 4477 )
#pragma warning( disable : 4313 )
int enumerateUsers( int argc,
	wchar_t* argv )
{
	LPUSER_INFO_0 pBuf = nullptr;
	LPUSER_INFO_0 pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = nullptr;

	if ( argc > 2 )
	{
		fwprintf( stderr, L"Usage: %s [\\\\ServerName]\n", argv[0] );
		exit( 1 );
	}

	// The server is not the default local computer.
	if ( argc == 2 )
	{
		pszServerName =  (LPTSTR) argv[1];
	}
	wprintf( L"\nUser account on %s: \n", pszServerName );

	// NetUserEnum with info level 0 - enumerate global user account types only.
	do
	{
		nStatus = NetUserEnum( (LPCWSTR) pszServerName,
			dwLevel,
			FILTER_NORMAL_ACCOUNT, // global users
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle );
		// If the call succeeds,
		if ( ( nStatus == NERR_Success ) || ( nStatus == ERROR_MORE_DATA ) )
		{
			if ( ( pTmpBuf = pBuf ) != nullptr )
			{
				// Loop through the entries.
				for ( i = 0; i < dwEntriesRead; i++ )
				{
					ASSERT( pTmpBuf, "pTmpBuf is nullptr!");

					if ( pTmpBuf == nullptr )
					{
						fprintf( stderr, "An access violation has occurred\n" );
						break;
					}
					//
					//  Print the name of the user account.
					//
					wprintf( L"\t-- %s\n", pTmpBuf->usri0_name );

					pTmpBuf++;
					dwTotalCount++;
				}
			}
		}
		else// Otherwise, print the system error.
		{
			fprintf( stderr, "A system error has occurred: %d\n", nStatus );
		}
		if ( pBuf )
		{
			NetApiBufferFree( pBuf );
			pBuf = nullptr;
		}
	}
	// Continue to call NetUserEnum while 
	//  there are more entries. 
	// 
	while ( nStatus == ERROR_MORE_DATA );

	// Check again for allocated memory.
	if ( pBuf )
	{
		NetApiBufferFree( pBuf );
	}
	
	// Print the final count of users enumerated.
	fprintf( stderr, "\nTotal of %d entries enumerated\n", dwTotalCount );

	std::system( "pause" );
	return EXIT_SUCCESS;
}
#pragma warning( default : 4313 )
#pragma warning( default : 4477 )

void getUserGroups()
{
	wchar_t user[256];
	DWORD size = sizeof( user ) / sizeof( user[0] );
	GetUserNameW( user,
		&size );

	printf( "User: %S\n", user );
	printf( "Local groups: \n" );

	LPBYTE buffer;
	DWORD entries;
	DWORD total_entries;

	NetUserGetLocalGroups( nullptr,
		user,
		0,
		LG_INCLUDE_INDIRECT,
		&buffer,
		MAX_PREFERRED_LENGTH,
		&entries,
		&total_entries );

	LOCALGROUP_USERS_INFO_0 *groups = (LOCALGROUP_USERS_INFO_0*)buffer;
	for ( DWORD i = 0; i < entries; i++ )
	{
		printf( "\t%S\n", groups[i].lgrui0_name );
	}
	NetApiBufferFree( buffer );

	printf( "Global groups: \n" );

	NetUserGetGroups( nullptr,
		user,
		0,
		&buffer,
		MAX_PREFERRED_LENGTH,
		&entries,
		&total_entries );

	GROUP_USERS_INFO_0* ggroups = (GROUP_USERS_INFO_0*)buffer;
	for ( DWORD i = 0; i < entries; ++i )
	{
		printf( "\t%S\n", ggroups[i].grui0_name );
	}
	NetApiBufferFree( buffer );
}

/*
Each application that requires the administrator access token must prompt the administrator for consent. The one exception is the relationship that exists between parent and child processes. Child processes inherit the user access token from the parent process. Both the parent and child processes, however, must have the same integrity level. Windows Server 2012 protects processes by marking their integrity levels. Integrity levels are measurements of trust. A "high" integrity application is one that performs tasks that modify system data, such as a disk partitioning application, while a "low" integrity application is one that performs tasks that could potentially compromise the operating system, such as a Web browser. Applications with lower integrity levels cannot modify data in applications with higher integrity levels. When a standard user attempts to run an application that requires an administrator access token, UAC requires that the user provide valid administrator credentials.

//SECURITY_MANDATORY_UNTRUSTED_RID == 0x00000000L
//SECURITY_MANDATORY_LOW_RID == 0x00001000L
//SECURITY_MANDATORY_MEDIUM_RID == 0x00002000L
//SECURITY_MANDATORY_HIGH_RID == 0x00003000L
//SECURITY_MANDATORY_SYSTEM_RID == 0x00004000L
//SECURITY_MANDATORY_PROTECTED_PROCESS_RID == 0x00005000L
*/
std::pair<DWORD, std::string> getProcessIntegrityLevel( HANDLE h = nullptr )
{
	HANDLE hToken;
	if ( !h )
	{
		hToken = GetCurrentThreadEffectiveToken();
	}
	else
	{
		hToken = h;
	}
	TOKEN_MANDATORY_LABEL tokenInformation;	// specifies the mandatory integrity level for a token
	DWORD dwLengthNeeded;
	DWORD dwIntegrityLevel;
	HRESULT hres;

	int ret = GetTokenInformation( hToken,
		TokenIntegrityLevel,
		&tokenInformation,
		dwLengthNeeded,
		&dwLengthNeeded );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	if ( ret )
	 {
		dwIntegrityLevel = *GetSidSubAuthority( tokenInformation.Label.Sid,
			(DWORD)(UCHAR)( *GetSidSubAuthorityCount( tokenInformation.Label.Sid ) - 1 ) );
		ASSERT_HRES_WIN32_IF_FAILED( hres );

		if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID )
		{
			return {dwIntegrityLevel, "Low"};
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID
			&& dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID )
		{
			return {dwIntegrityLevel, "Medium"};
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID
			&& dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID )
		{
			return {dwIntegrityLevel, "High"};
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID )
		{
			return {dwIntegrityLevel, "System"};
		}
	}
	return {0, "Unknown"};
}

// is process running with administrative rights
DWORD isProcessElevated()
{
	DWORD ret = FALSE;
	HANDLE hToken = nullptr;
	if ( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
	{
		TOKEN_ELEVATION elevation;
		DWORD cbSize = sizeof TOKEN_ELEVATION;
		if ( GetTokenInformation( hToken, TokenElevation, &elevation, sizeof( elevation ),
			&cbSize ) )
		{
			ret = elevation.TokenIsElevated;
		}
	}
	if ( hToken )
	{
		CloseHandle( hToken );
	}
	return ret;
}

bool isUserAnAdmin2()
{
	struct Data
	{
		PACL   pACL;
		PSID   psidAdmin;
		HANDLE hToken;
		HANDLE hImpersonationToken;
		PSECURITY_DESCRIPTOR     psdAdmin;
		Data() : pACL(nullptr), psidAdmin(nullptr), hToken(nullptr),
			hImpersonationToken(nullptr), psdAdmin(nullptr)
		{}
		~Data()
		{
			if (pACL) 
				LocalFree(pACL);
			if (psdAdmin) 
				LocalFree(psdAdmin);
			if (psidAdmin) 
				FreeSid(psidAdmin);
			if (hImpersonationToken) 
				CloseHandle (hImpersonationToken);
			if (hToken) 
				CloseHandle (hToken);
		}
	} data;

	BOOL   fReturn         = FALSE;
	DWORD  dwStatus;
	DWORD  dwAccessMask;
	DWORD  dwAccessDesired;
	DWORD  dwACLSize;
	DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
	
	PRIVILEGE_SET   ps;
	GENERIC_MAPPING GenericMapping;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
	
	if (!OpenThreadToken (GetCurrentThread(), TOKEN_DUPLICATE|TOKEN_QUERY, TRUE, &data.hToken))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
			return false;
	
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_QUERY, &data.hToken))
			return false;
	}
	
	if (!DuplicateToken (data.hToken, SecurityImpersonation, &data.hImpersonationToken))
		return false;
	
	if (!AllocateAndInitializeSid(&SystemSidAuthority, 2,
								SECURITY_BUILTIN_DOMAIN_RID,
								DOMAIN_ALIAS_RID_ADMINS,
								0, 0, 0, 0, 0, 0, &data.psidAdmin))
		return false;
	
	data.psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (data.psdAdmin == nullptr)
		return false;
	
	if (!InitializeSecurityDescriptor(data.psdAdmin, SECURITY_DESCRIPTOR_REVISION))
		return false;
	
	// Compute size needed for the ACL.
	dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(data.psidAdmin) - sizeof(DWORD);
	
	data.pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
	if (data.pACL == nullptr)
		return false;
	
	if (!InitializeAcl(data.pACL, dwACLSize, ACL_REVISION2))
		return false;
	
	dwAccessMask = ACCESS_READ | ACCESS_WRITE;
	
	if (!AddAccessAllowedAce(data.pACL, ACL_REVISION2, dwAccessMask, data.psidAdmin))
		return false;
	
	if (!SetSecurityDescriptorDacl(data.psdAdmin, TRUE, data.pACL, FALSE))
		return false;
	
	// AccessCheck validates a security descriptor somewhat; set the group
	// and owner so that enough of the security descriptor is filled out 
	// to make AccessCheck happy.
	
	SetSecurityDescriptorGroup(data.psdAdmin, data.psidAdmin, FALSE);
	SetSecurityDescriptorOwner(data.psdAdmin, data.psidAdmin, FALSE);
	
	if (!IsValidSecurityDescriptor(data.psdAdmin))
		return false;
	
	dwAccessDesired = ACCESS_READ;
	
	GenericMapping.GenericRead    = ACCESS_READ;
	GenericMapping.GenericWrite   = ACCESS_WRITE;
	GenericMapping.GenericExecute = 0;
	GenericMapping.GenericAll     = ACCESS_READ | ACCESS_WRITE;
	
	if (!AccessCheck(data.psdAdmin, data.hImpersonationToken, dwAccessDesired,
					&GenericMapping, &ps, &dwStructureSize, &dwStatus,
					&fReturn))
	{
		return false;
	}
	
	return fReturn;
}

bool isUserAnAdmin()
{
	bool b;
	wchar_t username[256];
	DWORD size = sizeof username;
	USER_INFO_1* userInfo;

	GetUserNameW( username,
		&size );

	DWORD ret = NetUserGetInfo( nullptr,
		username,
		1,
		(BYTE**) &userInfo );
	if ( ret != NERR_Success )
	{
		return false;
	}

	b = userInfo->usri1_priv == USER_PRIV_ADMIN;

	NetApiBufferFree( userInfo );
	return b;
}

// For systems with < 64 CPUs - otherwise set processor group with SetThreadIdealProcessorEx
DWORD pinThreadToCore( HANDLE hThread,
	DWORD core )
{
	DWORD previousPreferredCore = SetThreadIdealProcessor( hThread,
		4 );
	return previousPreferredCore;
}

enum class NTTHREAD_INFO
{
	ThreadBasicInformation = 0x00,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	/*unknown, 3.10 only*/
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	ThreadCpuAccountingInformation,
	ThreadSuspendCount,
	/* NT 10 and higher ...
	ThreadHeterogeneousCpuPolicy,
	ThreadContainerId,
	ThreadNameInformation,
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation,
	ThreadActualGroupAffinity*/
};

// demo threadMain
DWORD WINAPI threadMain( LPVOID p )
{
	while ( true )
	{
		if ( IsDebuggerPresent() )
		{
			//__debugbreak();
		}
	}
	return 0;
}

bool hideThreadFromDebugger( HANDLE hThread = nullptr )
{
	HRESULT hres;
	KeyConsole& console = KeyConsole::getInstance();
	DWORD tid = 0;

	if ( !hThread )
	{
		hThread = CreateThread( nullptr,
			0,
			threadMain,
			nullptr,
			0,
			&tid );
	}

	HMODULE hDLL = LoadLibraryW( TEXT( "ntdll.dll" ) );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	using SetInformationThread_t = NTSTATUS (WINAPI *)( HANDLE, NTTHREAD_INFO, PVOID, ULONG );
	using QueryInformationThread_t = NTSTATUS (WINAPI *)( HANDLE, NTTHREAD_INFO, PVOID, ULONG, PULONG );

	SetInformationThread_t pSetInformationThread = (SetInformationThread_t) GetProcAddress( hDLL,
		"NtSetInformationThread" );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	QueryInformationThread_t pQueryInformationThread = (QueryInformationThread_t) GetProcAddress( hDLL,
		"NtQueryInformationThread" );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	NTTHREAD_INFO infoClass = NTTHREAD_INFO::ThreadHideFromDebugger;	// thread information class to be set/queried
	DWORD infoHidden = 2u;	// thread information value to be set/queried
	int ret = -1;
	DWORD len = 0;
	
	// TODO: error - information record length is erroneous
	ret = pSetInformationThread( hThread,
		infoClass,
		&infoHidden,
		sizeof DWORD );
	ASSERT_NTSTATUS_IF_FAILED( ret );
	ret = pQueryInformationThread( hThread,
		infoClass,
		&infoHidden,
		sizeof DWORD,
		&len );
	ASSERT_NTSTATUS_IF_FAILED( ret );

	using namespace std::string_literals;
	console.print( "Thread "s + ( infoHidden == 1 ? "is"s : "is not"s ) + " hidden.\n"s );

	WaitForSingleObject( hThread,
		INFINITE );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	return true;
}

void RetrieveCallstack( HANDLE hThread )
{
	/*
	STACKFRAME64 stack{};
	// Initialize 'stack' with some required stuff.
	StackWalk64( IMAGE_FILE_MACHINE_I386,
		m_cProcessInfo.hProcess,
		hThread,
		&stack,
		&context,
		_ProcessMemoryReader,
		SymFunctionTableAccess64,
		SymGetModuleBase64,
		0 );*/
}

// typically used with true to suspend all other threads in the current process,
//	perform some critical modifications and then resume them (call again with false)
void setSuspendOtherThreads( bool bSuspend )
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD,
		0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		THREADENTRY32 te;
		te.dwSize = sizeof THREADENTRY32;
		Thread32First( hSnapshot,
			&te );
		HRESULT hres;
		ASSERT_HRES_WIN32_IF_FAILED( hres );
		do
		{
			if ( te.dwSize >= ( offsetof( THREADENTRY32, th32OwnerProcessID ) + sizeof DWORD )
				&& te.th32OwnerProcessID == GetCurrentProcessId()
				&& te.th32ThreadID != GetCurrentThreadId() )
			{

				HANDLE hThread = ::OpenThread( THREAD_ALL_ACCESS,
					FALSE,
					te.th32ThreadID );
				if ( hThread != nullptr )
				{
					if ( bSuspend )
					{
						SuspendThread( hThread );
					}
					else
					{
						ResumeThread( hThread );
					}
					CloseHandle( hThread );
				}
			}
		} while ( Thread32Next( hSnapshot, &te ) );

	}
}

// you can only change the protection of an entire page not a portion of it
void writeProtectedMemory( void* p,
	char* pData,
	int nBytes )
{
	HRESULT hres;
	DWORD oldProtection;
	
	VirtualProtect( p,
		nBytes,
		PAGE_EXECUTE_READWRITE,
		&oldProtection );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	memcpy( p, pData, nBytes );

	// restore page to its former status
	VirtualProtect( p,
		nBytes,
		oldProtection,
		nullptr );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
}

void zwEmumProcessModules( DWORD pid )
{
	struct NTUNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};
	
	enum MEMORY_INFORMATION
	{
		MemoryBasicInformation,
		MemoryWorkingSetList,
		MemorySectionName
	};
	
	struct FUNCTION_INFORMATION
	{
		char name[64];
		ULONG_PTR VirtualAddress;
	};
	
	struct MODULE_INFORMATION
	{
		PVOID BaseAddress;
		PVOID AllocationBase;
		DWORD AllocationProtect;
		SIZE_T RegionSize;
		DWORD State;
		DWORD Protect;
		DWORD Type;
		WCHAR szPathName[MAX_PATH];
		PVOID EntryAddress;
		FUNCTION_INFORMATION* Functions;
		DWORD FunctionCount;
		DWORD SizeOfImage;
	};

	using TZwQueryVirtualMemory = LONG (WINAPI *)( HANDLE ProcessHandle,
		PVOID BaseAddress,
		MEMORY_INFORMATION MemoryInformationClass,
		PVOID MemoryInformation,
		ULONG MemoryInformationLength,
		PULONG ReturnLength );
 
	HRESULT hres;
	HANDLE hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE,
		pid );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
 
	HANDLE hProc = OpenProcess( PROCESS_ALL_ACCESS,
		FALSE,
		pid );
 
	MODULEENTRY32W me32;
	BYTE szBuffer[MAX_PATH * 2 + 4]{};
	WCHAR szModuleName[MAX_PATH]{};
	WCHAR szPathName[MAX_PATH]{};
	MEMORY_BASIC_INFORMATION mbi;
	MODULE_INFORMATION mi;
	PUNICODE_STRING usSectionName;
	ULONG_PTR dwStartAddr;
	me32.dwSize = sizeof MODULEENTRY32W;
 
	TZwQueryVirtualMemory fnZwQueryVirtualMemory;
	fnZwQueryVirtualMemory = (TZwQueryVirtualMemory)::GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
		"ZwQueryVirtualMemory" );
 
	Module32FirstW( hModuleSnap,
		&me32 );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	dwStartAddr = (ULONG_PTR)me32.modBaseAddr;
	if ( hProc && fnZwQueryVirtualMemory )
	{
		if ( fnZwQueryVirtualMemory( hProc, (PVOID)dwStartAddr, MemoryBasicInformation, &mbi, sizeof( mbi ), nullptr ) >= 0 )
		{
			if ( mbi.Type == MEM_IMAGE )
			{
				if ( fnZwQueryVirtualMemory( hProc, (PVOID)dwStartAddr, MemorySectionName, szBuffer, sizeof szBuffer, nullptr ) >= 0 )
				{
					memset( &mi, 0, sizeof MODULE_INFORMATION );
					memcpy( &mi, &mbi, sizeof MEMORY_BASIC_INFORMATION );
					usSectionName = (PUNICODE_STRING)szBuffer;
					wcsncpy_s( szModuleName, usSectionName->Buffer, usSectionName->Length / sizeof WCHAR );
					szModuleName[usSectionName->Length / sizeof(WCHAR)] = UNICODE_NULL;
					printf( "%S\n",usSectionName->Buffer );
				}
			}
		}
	}
	while ( Module32NextW( hModuleSnap, &me32 ) )
	{
		dwStartAddr = (ULONG_PTR)me32.modBaseAddr;
		if ( hProc && fnZwQueryVirtualMemory )
		{
			if ( fnZwQueryVirtualMemory( hProc, (PVOID)dwStartAddr, MemoryBasicInformation, &mbi, sizeof mbi, nullptr ) >= 0 )
			{
				if ( mbi.Type == MEM_IMAGE )
				{
					if ( fnZwQueryVirtualMemory( hProc, (PVOID)dwStartAddr, MemorySectionName, szBuffer, sizeof szBuffer, nullptr ) >= 0 )
					{
						memset( &mi, 0, sizeof MODULE_INFORMATION );
						memcpy( &mi, &mbi, sizeof MEMORY_BASIC_INFORMATION );
						usSectionName = (PUNICODE_STRING)szBuffer;
						printf( "%S\n", usSectionName->Buffer );
					}
				}
			}
		}
	}
}

// eg. title = "Calculator"
HWND getWindowByTitle( const std::string& title )
{
	return FindWindowW( nullptr,
		util::s2ws( title ).data() );
}


struct WindowData
{
	unsigned long m_pid;
	HWND m_hWnd;
};

BOOL isMainWindow( HWND hWnd )
{   
	return GetWindow( hWnd, GW_OWNER ) == nullptr
		&& IsWindowVisible( hWnd );
}

BOOL CALLBACK enumWindowsCallback( HWND handle,
	LPARAM lParam )
{
	WindowData& wd =  *reinterpret_cast<WindowData*>( lParam );
	unsigned long pid = 0;
	GetWindowThreadProcessId( handle,
		&pid );
	if ( wd.m_pid != pid || !isMainWindow( handle ) )
	{
		return true;
	}
	wd.m_hWnd = handle;
	return false;
}

HWND getProcessMainWindow( unsigned pid )
{
	WindowData wd;
	wd.m_pid = pid;
	wd.m_hWnd = nullptr;
	EnumWindows( enumWindowsCallback,
		(LPARAM)&wd );
	return wd.m_hWnd;
}

HMODULE getProcessHandle_impl( DWORD pid,
	const std::wstring& procName )
{
	HRESULT hres;
	wchar_t szTestedProcessName[MAX_PATH] = L"<unknown>";
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	HMODULE hModule;
	if ( hProcess != nullptr)
	{
		DWORD nBytesWritten = 0;

		if ( EnumProcessModulesEx( hProcess,
			&hModule,
			sizeof hModule,
			&nBytesWritten,
			LIST_MODULES_32BIT | LIST_MODULES_64BIT ) )
		{
			GetModuleBaseNameW( hProcess,
				hModule,
				szTestedProcessName,
				sizeof( szTestedProcessName ) / sizeof( char ) );
			if ( !_wcsicmp( procName.c_str(), szTestedProcessName ) )
			{
				CloseHandle( hProcess );
				return hModule;
			}
		}
	}
	CloseHandle( hProcess );
	return nullptr;
}

// eg. Notepad.exe
HMODULE getProcessHandle( const std::wstring& procName )
{
	HRESULT hres;
	DWORD processes[1024];
	DWORD bytesRequired;

	EnumProcesses( processes,
		sizeof( processes ),
		&bytesRequired );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	// calculate how many process identifiers were returned.
	DWORD nProcesses = bytesRequired / sizeof( DWORD );

	HMODULE hModule;
	for ( DWORD i = 0; i < nProcesses; i++ )
	{
		hModule = getProcessHandle_impl( processes[i],
			procName );
		if ( hModule )
		{
			break;
		}
	}
	return hModule;
}

DWORD getProcessIdByWindowTitle( const std::wstring& windowTitle )
{
	auto szWindowName = windowTitle.c_str();
	HWND hWnd = FindWindowW( nullptr,
		szWindowName );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	DWORD pid;
	GetWindowThreadProcessId( hWnd,
		&pid );
	return pid;
}

HANDLE getProcessHandleByWindowTitle( const std::wstring& windowTitle,
	DWORD rights = PROCESS_ALL_ACCESS )
{
	auto pid = getProcessIdByWindowTitle( windowTitle );
	HANDLE hProc = OpenProcess( rights,
		false,
		pid );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	//printProcessModules( pid );
	//printProcessThreads( pid );
	return hProc;
}

bool printProcessModules( DWORD pid )
{
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32W moduleEntry{};
	// set the size of the structure before using it.
	moduleEntry.dwSize = sizeof( MODULEENTRY32W );

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE,
		pid );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	if ( !Module32FirstW( hSnapshot, &moduleEntry ) )
	{
		CloseHandle( hSnapshot );
		return false;
	}
	// walk the module list of the process and display info
	do
	{
		std::cout << "\n\nmodule name = " << moduleEntry.szModule
			<< "\nexe path = " << moduleEntry.szExePath
			<< "\npid = " << moduleEntry.th32ProcessID
			<< "\nRef count (g) = " << moduleEntry.GlblcntUsage
			<< "\nRef count (p) = " << moduleEntry.ProccntUsage
		//<< "\nBase address = " << moduleEntry.modBaseAddr
			<< "\nBase size = " << moduleEntry.modBaseSize;
	} while( Module32NextW( hSnapshot, &moduleEntry ) );

	CloseHandle( hSnapshot );
	return true;
}

bool printProcessThreads( DWORD pid ) 
{ 
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 threadEntry{};
	// set the size of the structure before using it
	threadEntry.dwSize = sizeof( THREADENTRY32 );

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD,
		0 );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	if ( !Thread32First( hSnapshot, &threadEntry ) )
	{
		CloseHandle( hSnapshot );
		return false;
	}
	// walk the thread list of the process and display info
	do
	{
		if ( threadEntry.th32OwnerProcessID == pid )
		{
			std::cout << "\n\nthread id = " << threadEntry.th32ThreadID
				<< "\nbase priority = " << threadEntry.tpBasePri
				<< "\ndelta priority = " << threadEntry.tpDeltaPri;
		}
	} while ( Thread32Next( hSnapshot, &threadEntry ) );

	CloseHandle( hSnapshot );
	return true;
}

bool printProcesses()
{
	static HANDLE hProc;
	PROCESSENTRY32W processEntry{};
	// set the size of the structure before using it
	processEntry.dwSize = sizeof( PROCESSENTRY32W );
	DWORD priority;

	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS,
		0 );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	// retrieve information about the first process
	if ( !Process32FirstW( hSnapshot, &processEntry ) )
	{
		// clean the snapshot object
		CloseHandle( hSnapshot );
		return false;
	}
	// enumerate the rest
	while ( Process32NextW( hSnapshot, &processEntry ) )
	{
		std::cout << "\n\nprocess name = " << processEntry.szExeFile
			<< "\npid = " << processEntry.th32ProcessID
			<< "\nthread count = " << processEntry.cntThreads
			<< "\nparent's pid = " << processEntry.th32ParentProcessID
			<< "\npriority base = " << processEntry.pcPriClassBase;
		priority = GetPriorityClass( hProc );
		if ( priority )
		{
			std::cout << "\npriority = " << priority;
		}
	}

	CloseHandle( hSnapshot );					// clean the snapshot object
	return true;
}

MODULEINFO getModuleInfo( HMODULE hModule )
{
	MODULEINFO moduleInfo{};
	ASSERT( hModule, "hModule is null!" );
	GetModuleInformation( GetCurrentProcess(),
		hModule,
		&moduleInfo,
		sizeof MODULEINFO );
	return moduleInfo;
}

MODULEINFO getModuleInfo( const char* szModule )
{
	ASSERT( szModule, "module name is null!" );
	MODULEINFO moduleInfo{};
	HMODULE hModule = GetModuleHandleA( szModule );
	GetModuleInformation( GetCurrentProcess(),
		hModule,
		&moduleInfo,
		sizeof MODULEINFO );
	return moduleInfo;
}

// get process dll base address
HMODULE getProcessModule( HANDLE hProc,
	const char* szRequestedModuleName )
{
	char* requestedModuleNameLowerCase = nullptr;
	strcpy( requestedModuleNameLowerCase, szRequestedModuleName );
	_strlwr_s( requestedModuleNameLowerCase,
		strlen( szRequestedModuleName ) + 1 );

	HMODULE processModules[1024];
	DWORD nBytesWritten = 0;
	int ret = EnumProcessModules( hProc,
		processModules,
		sizeof( HMODULE ) * 1024,
		&nBytesWritten );
	KeyConsole& console = KeyConsole::getInstance();
	console.log( "The module was not found in the specified process." );

	DWORD nModules = nBytesWritten / sizeof HMODULE;
	char procName[256];
	GetModuleFileNameExA( hProc,
		nullptr,
		procName,
		256 );
	// a null module handle gets the process name
	_strlwr_s( procName,
		256 );

	HMODULE hModule = nullptr;
	for ( DWORD i = 0; i < nModules; ++i )
	{
		char moduleName[256];
		CHAR absoluteModulePath[256];
		CHAR rebasedPath[256] = { 0 };
		GetModuleFileNameExA( hProc,
			processModules[i],
			moduleName,
			256 );
		_strlwr_s( moduleName,
			256 );
		char* lastSlash = strrchr( moduleName,
			'\\' );
		if ( !lastSlash )
		{
			lastSlash = strrchr( moduleName,
				'/' );
		}
		char* dllName = lastSlash + 1;
		if ( strcmp( dllName, requestedModuleNameLowerCase ) == 0 )
		{
			hModule = processModules[i];
			MODULEINFO moduleInfo = getModuleInfo( processModules[i] );

			return hModule;
		}
		// the following string operations are to account for cases where GetModuleFileNameEx
		// returns a relative path rather than an absolute one, the path we get to the module
		// is using a virtual drive letter (ie: one created by subst) rather than a real drive
		char* ret = _fullpath( absoluteModulePath,
			moduleName,
			256 );
		ASSERT( ret, "resolved module path is null!" );
	}
	return nullptr;
}

bool setProcessDebugPrivileges( HANDLE hProc )
{
	HRESULT hres;
	HANDLE hToken;
	TOKEN_PRIVILEGES newPrivileges;
	LUID luid;

	OpenProcessToken( hProc,
		TOKEN_ADJUST_PRIVILEGES,
		&hToken );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	LookupPrivilegeValueW( nullptr,
		L"seDebugPrivilege",
		&luid );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	newPrivileges.PrivilegeCount = 1;
	newPrivileges.Privileges[0].Luid = luid;
	newPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	int ret = AdjustTokenPrivileges( hToken,
		false,
		&newPrivileges,
		0,
		nullptr,
		nullptr );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	CloseHandle( hToken );
	return true;
}

// may return Null on failure
std::vector<BYTE> queryProcessInformation( HANDLE hProc,
	PROCESSINFOCLASS infoClass = ProcessBasicInformation )
{
	using TNtQueryInformationProcess = NTSTATUS( __stdcall * ) ( HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength, PULONG ReturnLength );

	static TNtQueryInformationProcess ntQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
		"NtQueryInformationProcess" );
	if ( ntQueryInformationProcess == nullptr )
	{
		return {};
	}

	std::vector<BYTE> info;
	ULONG infoLen = 128;	// should be enough
	info.reserve( infoLen );
	ULONG retLen;

	NTSTATUS ret = ntQueryInformationProcess( hProc,
		infoClass,
		info.data(),
		infoLen,
		&retLen );
	ASSERT_NTSTATUS_IF_FAILED( ret );
	ASSERT( info.size() >= 4, "Process information vector is empty!" );
	return info;
}

//===================================================
//	\function	getPeb
//	\brief  Process Environment Block
//			https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
//	\date	2021/08/29 1:05
PPEB getPeb()
{
	static PPEB pPeb;
	thread_local PTEB pTeb;
#if defined _WIN64 || defined _M_X64
	pTeb = reinterpret_cast<PTEB>( __readgsqword( reinterpret_cast<UINT64>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#else
	pTeb = reinterpret_cast<PTEB>( __readfsdword( reinterpret_cast<UINT64>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#endif
	pPeb = pTeb->ProcessEnvironmentBlock;
	return pPeb;
}

PTEB getTeb()
{
	thread_local PTEB pTeb;
#if defined _WIN64 || defined _M_X64
	pTeb = reinterpret_cast<PTEB>( __readgsqword( reinterpret_cast<UINT64>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#else
	pTeb = reinterpret_cast<PTEB>( __readfsdword( reinterpret_cast<UINT64>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#endif
	return pTeb;
}

#if defined _WIN64 || defined __x86_64__ || defined __ppc64__
// If GetModuleHandle is hooked this won't work
HANDLE getCurrentProcessBaseAddress()
{
#	ifdef THIS_INSTANCE
	return THIS_INSTANCE;
#	else
	const PPEB pPeb = reinterpret_cast<PPEB>( __readgsqword( 0x60 ) );
	return pPeb->Reserved3[1];
#	endif
}
#else
HANDLE getCurrentProcessBaseAddress()
{
#	ifdef THIS_INSTANCE
	return THIS_INSTANCE;
#	else
	const PPEB pPeb = reinterpret_cast<PPEB>( __readfsdword( 0x30 ) );
	return pPeb->Reserved3[1];
#	endif
}
#endif

HMODULE getModuleBaseAddress( HANDLE hProc,
	const std::wstring& modName )
{
	HMODULE modules[1024];
	DWORD nBytesWritten;
	if ( EnumProcessModules( hProc, modules, sizeof( modules ), &nBytesWritten ) )
	{
		const DWORD nModules = nBytesWritten / sizeof( HMODULE );
		for ( unsigned i = 0; i < nModules; ++i )
		{
			TCHAR szModuleName[MAX_PATH];
			const DWORD nChars = sizeof( szModuleName ) / sizeof( TCHAR );
			if ( GetModuleFileNameEx( hProc, modules[i], szModuleName, nChars ) )
			{
				const std::wstring moduleName{szModuleName};
				if ( moduleName.find( modName ) != std::string::npos )
				{
					return modules[i];
				}
			}
		}
	}
	return nullptr;
}

HMODULE getModuleBaseAddress( const std::wstring& windowTitle,
	const std::wstring& modName )
{
	const auto hProc = getProcessHandleByWindowTitle( windowTitle,
		 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION );

	HMODULE modules[1024];
	DWORD nBytesWritten;
	if ( EnumProcessModules( hProc, modules, sizeof( modules ), &nBytesWritten ) )
	{
		const DWORD nModules = nBytesWritten / sizeof( HMODULE );
		for ( unsigned i = 0; i < nModules; ++i )
		{
			TCHAR szModuleName[MAX_PATH];
			const DWORD nChars = sizeof( szModuleName ) / sizeof( TCHAR );
			if ( GetModuleFileNameEx( hProc, modules[i], szModuleName, nChars ) )
			{
				const std::wstring moduleName{szModuleName};
				if ( moduleName.find( modName ) != std::string::npos )
				{
					return modules[i];
				}
			}
		}
	}
	return nullptr;
}

template<typename T>
T readProcessMemory( HANDLE hProc,
	void* pAddr )
{
	T readVal;
	std::size_t bytesRead = 0;
	ReadProcessMemory( hProc,
		pAddr,
		&readVal,
		sizeof T,
		&bytesRead );
	ASSERT( bytesRead > 0, "Nothing was read!" );
	return readVal;
}

template<typename T>
std::size_t writeProcessMemory( HANDLE hProc,
	void* pAddr,
	T val )
{
	std::size_t bytesWritten = 0;
	WriteProcessMemory( hProc,
		pAddr,
		&val,
		sizeof T,
		&bytesWritten );
	ASSERT( bytesWritten > 0, "Nothing was written!" );
	return bytesWritten;
}

void spawnProcess( LPCWSTR programPath )
{
	HRESULT hres;
	STARTUPINFOW si;	// set various window & thread properties
	ZeroMemory( &si, sizeof STARTUPINFOW );
	PROCESS_INFORMATION pi;
	ZeroMemory( &pi, sizeof PROCESS_INFORMATION );
	si.cb = sizeof STARTUPINFOW ;

	int ret = CreateProcessW( programPath,
		nullptr,				// command line to be executed
		nullptr,				// process handle not inheritable
		nullptr,				// thread handle not inheritable
		false,					// no handle inheritance
		0,						// creation flags
		nullptr,				// use parent's environment block
		nullptr,				// use parent's starting directory 
		&si,
		&pi );
	ASSERT_HRES_WIN32_IF_FAILED( hres );

	WaitForSingleObject( pi.hProcess,
		INFINITE );
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );
}

//////////////////////////////////////////////////////////////////////
void tests()
{
	const std::wstring targetWindowTitle = L"Calculator";
	const std::wstring procName = L"calc.exe";
	const auto procBaseAddr = getModuleBaseAddress( targetWindowTitle,
		procName );
	if ( !procBaseAddr )
	{
		std::cout << "Process not found!\n";
	}
	std::cout << procBaseAddr
		<< '\n';
	
	std::cout << "getCurrentProcessBaseAddress:"
		<< '\n';
	std::cout << getCurrentProcessBaseAddress()
		<< '\n';
	std::cout << THIS_INSTANCE
		<< '\n';
	
	std::cout << "queryProcessHandle\n";
	getProcessHandle( L"Stopwatch.exe" );
	
	auto ret = getProcessIntegrityLevel();
	if ( ret.first != 0 )
	{
#if defined _DEBUG && !defined NDEBUG
		KeyConsole& console = KeyConsole::getInstance();
		console.print( ret.second );
#endif
	}
	
	spawnProcess( L"C:\\Windows\\System32\\calc.exe" );

	hideThreadFromDebugger();
}
//////////////////////////////////////////////////////////////////////


int WINAPI wWinMain( HINSTANCE hInst,
	HINSTANCE hPrevInstance,
	wchar_t* szConsole,
	int nShowCmd )
{
	constexpr const bool bTesting = false;
	
	if ( bTesting )
	{
		tests();
	}
	else
	{
		// Change ammo value in COD4
		DWORD* pAmmo = reinterpret_cast<DWORD*>( 0x00e0db44 );	// RVA of ammo in COD4
		DWORD readAmmo = 0;
		SIZE_T bytesRead = 0;
		int desiredAmmo;
		SIZE_T bytesWritten = 0;

		std::wstring windowTitle{L"Call of Duty 4"};
		auto szWindowTitle = windowTitle.c_str();

		HANDLE hProc = getProcessHandleByWindowTitle( windowTitle );
		if ( !hProc )
		{
			help();
			return -1;
		}
		std::cout << "We have access.\n";

		// now that we have access to the process you can do whatever you want with it..

		// read and display ammo value every second
		while ( !( GetAsyncKeyState( VK_F9 ) & 1 ) )
		{
			readAmmo = readProcessMemory<DWORD>( hProc,
				pAmmo );
#if defined _DEBUG && !defined NDEBUG
			KeyConsole& console = KeyConsole::getInstance();
			console.print( std::to_string( readAmmo ) + '\n' );
#endif
			Sleep( 1000 );
		}

		// overwrite the value for funzies
		std::cout << "How much ammo do you want to have?\n";
#if defined _DEBUG && !defined NDEBUG
		KeyConsole& console = KeyConsole::getInstance();
		std::string ammoStr = console.read( 8 );
		desiredAmmo = std::atoi( ammoStr.c_str() );
		console.print( "you typed = " + std::to_string( desiredAmmo ) );
#else
		desiredAmmo = 100;
#endif
		bytesWritten = writeProcessMemory( hProc,
			pAmmo,
			desiredAmmo );
	}

#if defined _DEBUG && !defined NDEBUG
	KeyConsole::getInstance().resetInstance();
#endif
	return 0;
}