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
#include "utils.h"
#include "os_utils.h"
#include "assertions_console.h"

#pragma comment( lib, "netapi32.lib" )
#pragma comment( lib, "psapi.lib" )


void help()
{
	std::cout << "Make sure the requested resource is currently active!\n";
}


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

	if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, sRoot, 0, KEY_READ, &hUninstKey ) != ERROR_SUCCESS )
	{
		return false;
	}

	for ( DWORD dwIndex = 0; lResult == ERROR_SUCCESS; dwIndex++ )
	{
		// enumerate all sub keys...
		dwBufferSize = sizeof sAppKeyName;
		if ( (lResult = RegEnumKeyExW( hUninstKey, dwIndex, sAppKeyName,
			&dwBufferSize, nullptr, nullptr, nullptr, nullptr ) ) == ERROR_SUCCESS)
		{
			// open the sub key
			wsprintfW( sSubKey,
				L"%s\\%s",
				sRoot,
				sAppKeyName );
			if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, sSubKey, 0, KEY_READ, &hAppKey ) != ERROR_SUCCESS )
			{
				RegCloseKey( hAppKey );
				RegCloseKey( hUninstKey );
				return false;
			}

			//Get the display name value from the application's sub key.
			dwBufferSize = sizeof sDisplayName;
			if ( RegQueryValueExW( hAppKey, L"DisplayName", nullptr,
				&dwType, (unsigned char*)sDisplayName, &dwBufferSize ) == ERROR_SUCCESS )
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
	char *argv[ ] )
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
		//
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
		//
		// If the call succeeds,
		//
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRec>0;dwRec--)
			{
				//
				// Print the retrieved group information.
				//
				printf("Name:		%S\n"
						"Comment:	%S\n"
						"Group ID:  %u\n"
						"Attributes: %u\n"
						"--------------------------------\n",
						p->grpi3_name,
						p->grpi3_comment,
						p->grpi3_group_id,
						p->grpi3_attributes);
				//
				// If there is more data, set the index.
				//
				i = p->grpi3_next_index;
				p++;
			}
			//
			// Free the allocated memory.
			//
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
int enumerateUsers( int argc,
	char* argv )
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
	//
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
			if ( (pTmpBuf = pBuf) != nullptr )
			{
				// Loop through the entries.
				for (i = 0; (i < dwEntriesRead); i++)
				{
					ASSERT( pTmpBuf, "pTmpBuf is nullptr!");

					if (pTmpBuf == nullptr)
					{
						fprintf(stderr, "An access violation has occurred\n");
						break;
					}
					//
					//  Print the name of the user account.
					//
					wprintf(L"\t-- %s\n", pTmpBuf->usri0_name);

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
	while (nStatus == ERROR_MORE_DATA); // end do
	//
	// Check again for allocated memory.
	//
	if ( pBuf )
		NetApiBufferFree(pBuf);
	//
	// Print the final count of users enumerated.
	//
	fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);

	std::system( "pause" );
	return EXIT_SUCCESS;
}

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
	for ( int i=0; i<entries; i++ )
	{
		printf( "\t%S\n", groups[i].lgrui0_name );
	}
	NetApiBufferFree(buffer);

	printf( "Global groups: \n" );

	NetUserGetGroups( nullptr,
		user,
		0,
		&buffer,
		MAX_PREFERRED_LENGTH,
		&entries,
		&total_entries );

	GROUP_USERS_INFO_0* ggroups = (GROUP_USERS_INFO_0*)buffer;
	for ( int i=0; i<entries; i++ )
	{
		printf( "\t%S\n", ggroups[i].grui0_name );
	}
	NetApiBufferFree( buffer );
}

/*
Each application that requires the administrator access token must prompt the administrator for consent. The one exception is the relationship that exists between parent and child processes. Child processes inherit the user access token from the parent process. Both the parent and child processes, however, must have the same integrity level. Windows Server 2012 protects processes by marking their integrity levels. Integrity levels are measurements of trust. A "high" integrity application is one that performs tasks that modify system data, such as a disk partitioning application, while a "low" integrity application is one that performs tasks that could potentially compromise the operating system, such as a Web browser. Applications with lower integrity levels cannot modify data in applications with higher integrity levels. When a standard user attempts to run an application that requires an administrator access token, UAC requires that the user provide valid administrator credentials.
*/
//SECURITY_MANDATORY_UNTRUSTED_RID == 0x00000000L
//SECURITY_MANDATORY_LOW_RID == 0x00001000L
//SECURITY_MANDATORY_MEDIUM_RID == 0x00002000L
//SECURITY_MANDATORY_HIGH_RID == 0x00003000L
//SECURITY_MANDATORY_SYSTEM_RID == 0x00004000L
//SECURITY_MANDATORY_PROTECTED_PROCESS_RID == 0x00005000L
/*
DWORD getProcessIntegrityLevel()
{
	if ( GetTokenInformation( hToken, TokenIntegrityLevel, pTIL,
		dwLengthNeeded, &dwLengthNeeded ) )
	 {
		dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
		
		if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID )
		{
			// Low Integrity
			wprintf(L"Low Process");
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID
			&& dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID )
		{
			// Medium Integrity
			wprintf(L"Medium Process");
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID
			&& dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID )
		{
			// High Integrity
			wprintf(L"High Integrity Process");
		}
		else if ( dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID )
		{
			// System Integrity
			wprintf(L"System Integrity Process");
		}
	}
}
*/

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

/*
#pragma comment(lib, "user32.lib")

class Systeminfo final
{
public:
	Systeminfo();
	Systeminfo( const Systeminfo& rhs ) = delete;
	Systeminfo& operator=( const Systeminfo& rhs ) = delete;
	
	const std::string getFamily() const noexcept;
	const std::string getManufacturer() const noexcept;
	const std::string getProductName() const noexcept;
	const std::string getSerialNumber() const noexcept;
	const std::string getSku() const noexcept;
	const std::string getUuid() const noexcept;
	const std::string getVersion() const noexcept;

	   printf("Hardware information: \n");  
   printf("  OEM ID: %u\n", siSysInfo.dwOemId);
   printf("  Number of processors: %u\n", 
	  siSysInfo.dwNumberOfProcessors); 
   printf("  Page size: %u\n", siSysInfo.dwPageSize); 
   printf("  Processor type: %u\n", siSysInfo.dwProcessorType); 
   printf("  Minimum application address: %lx\n", 
	  siSysInfo.lpMinimumApplicationAddress); 
   printf("  Maximum application address: %lx\n", 
	  siSysInfo.lpMaximumApplicationAddress); 
   printf("  Active processor mask: %u\n", 
	  siSysInfo.dwActiveProcessorMask); 
private:
	std::string m_family;
	std::string m_manufacturer;
	std::string m_productName;
	std::string m_serialNumber;
	std::string m_sku;
	std::string m_uuid;
	std::string m_version;
};*/

void memcpyProtectedMemory( void* p,
	char* value,
	int nBytes )
{
	DWORD oldProtection;
	
	VirtualProtect( p,
		nBytes,
		PAGE_EXECUTE_READWRITE,
		&oldProtection );

	memcpy( p, value, nBytes );

	// restore page to its former status
	VirtualProtect( p,
		nBytes,
		oldProtection,
		nullptr );
}

MODULEINFO getModuleInfo( const char* szModule )
{
	MODULEINFO moduleInfo{};
	HMODULE hModule = GetModuleHandleA( szModule );
	if ( hModule == nullptr )
	{
		return moduleInfo;
	}
	GetModuleInformation( GetCurrentProcess(),
		hModule,
		&moduleInfo,
		sizeof MODULEINFO );
	return moduleInfo;
}

// eg. title = "calculator"
HWND getWindowByTitle( const std::string& title )
{
	return FindWindowW( nullptr,
		util::s2ws( title ).data() );
}


bool isProcess64bit( HANDLE handle )
{
	int bWow64 = false;
	IsWow64Process( handle,
		&bWow64 );

	if ( bWow64 )
	{
		return false;
	}
	else
	{
		SYSTEM_INFO sysInfo;
		GetSystemInfo( &sysInfo );
		return sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
	}
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

HWND fetchMainWindow( unsigned pid )
{
	WindowData wd;
	wd.m_pid = pid;
	wd.m_hWnd = nullptr;
	EnumWindows( enumWindowsCallback,
		(LPARAM)&wd );
	return wd.m_hWnd;
}


HMODULE getProcessHandleByExecutableName( DWORD pid,
	const std::wstring& exeName )
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
		DWORD nBytesRequired;

		if ( EnumProcessModulesEx( hProcess,
			&hModule,
			sizeof hModule,
			&nBytesRequired,
			LIST_MODULES_32BIT | LIST_MODULES_64BIT ) )
		{
			GetModuleBaseNameW( hProcess,
				hModule,
				szTestedProcessName,
				sizeof( szTestedProcessName ) / sizeof( char ) );
			if ( !_wcsicmp( exeName.c_str(), szTestedProcessName ) )
			{
				CloseHandle( hProcess );
				return hModule;
			}
		}
	}
	CloseHandle( hProcess );
	return nullptr;
}

HMODULE queryProcessHandle( const std::wstring& exeName )
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
	for ( int i = 0; i < nProcesses; i++ )
	{
		hModule = getProcessHandleByExecutableName( processes[i],
			 exeName );
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
	//listProcessModules( pid );
	//listProcessThreads( pid );
	return hProc;
}

bool listProcessModules( DWORD pid )
{
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32W moduleEntry{};
	// set the size of the structure before using it.
	moduleEntry.dwSize = sizeof( MODULEENTRY32W );

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE,
		pid );
	ASSERT( hSnapshot != INVALID_HANDLE_VALUE, "Couldn't create snapshot!" );
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

bool listProcessThreads( DWORD pid ) 
{ 
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 threadEntry{};
	// set the size of the structure before using it
	threadEntry.dwSize = sizeof( THREADENTRY32 );

	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD,
		0 );
	ASSERT( hSnapshot != INVALID_HANDLE_VALUE, "Couldn't create snapshot!" );
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

bool listProcesses()
{
	static HANDLE hProc;
	PROCESSENTRY32W processEntry{};
	// set the size of the structure before using it
	processEntry.dwSize = sizeof( PROCESSENTRY32W );
	DWORD priority;

	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS,
		0 );
	ASSERT( hSnapshot != INVALID_HANDLE_VALUE, "Couldn't create snapshot!" );
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

#if _WIN64
// If GetModuleHandle is hooked this won't work
HANDLE getCurrentProcessBaseAddress()
{
	return GetModuleHandle( nullptr );
}
#else
HANDLE getCurrentProcessBaseAddress()
{
	const PPEB pPeb = reinterpret_cast<PPEB>( __readfsdword( 0x30 ) );
	return pPeb->Reserved3[1];
}
#endif

HMODULE getProcessBaseAddress( const std::wstring& windowTitle,
	const std::wstring& exeName )
{
	const auto hProc = getProcessHandleByWindowTitle( windowTitle,
		 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION );

	HMODULE hModules[1024];
	DWORD requiredBytes;
	if ( EnumProcessModules( hProc, hModules, sizeof( hModules ), &requiredBytes ) )
	{
		const DWORD nModules = requiredBytes / sizeof( HMODULE );
		for ( unsigned i = 0; i < nModules; ++i )
		{
			TCHAR szModuleName[MAX_PATH];
			const DWORD nChars = sizeof( szModuleName ) / sizeof( TCHAR );
			if ( GetModuleFileNameEx( hProc, hModules[i], szModuleName, nChars ) )
			{
				const std::wstring moduleName = szModuleName;
				if ( moduleName.find( exeName ) != std::string::npos )
				{
					return hModules[i];
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

//////////////////////////////////////////////////////////////////////
void tests()
{
	const std::wstring targetWindowTitle = L"Calculator";
	const std::wstring targetExe = L"calc.exe";
	const auto procBaseAddr = getProcessBaseAddress( targetWindowTitle,
		targetExe );
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

	queryProcessHandle( L"Stopwatch.exe" );
}
//////////////////////////////////////////////////////////////////////

#pragma comment( linker, "/SUBSYSTEM:WINDOWS" )

int WINAPI wWinMain( HINSTANCE hInst,
	HINSTANCE hPrevInstance,
	wchar_t* szConsole,
	int nShowCmd )
{
	//tests();

	DWORD* pAmmo = reinterpret_cast<DWORD*>( 0x00e0db44 );	// RVA of ammo in COD4
	DWORD readAmmo = 0;
	SIZE_T bytesRead = 0;
	int desiredAmmo;
	SIZE_T bytesWritten = 0;

	std::wstring processName{L"Call of Duty 4"};
	auto szProcessName = processName.c_str();

	HANDLE hProc = getProcessHandleByWindowTitle( processName );
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
		KeyConsole& console = KeyConsole::getInstance();
		console.print( std::to_string( readAmmo ) + '\n' );
		Sleep( 1000 );
	}

	// overwrite the value for funzies
	std::cout << "How much ammo do you want to have?\n";
	KeyConsole& console = KeyConsole::getInstance();
	std::string ammoStr = console.read( 8 );
	desiredAmmo = std::atoi( ammoStr.c_str() );
	console.print( "you typed = " + std::to_string( desiredAmmo ) );
	bytesWritten = writeProcessMemory( hProc,
		pAmmo,
		desiredAmmo );

	console.resetInstance();
	std::system( "pause" );
	return 0;
}
