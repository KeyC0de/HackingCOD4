#include "winner.h"
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <optional>
#include <winternl.h>
#include <psapi.h>
#include "util.h"


void help()
{
	std::cout << "Make sure your requested process is currently running!\n";
}

#pragma region convenientWrappers
std::optional<DWORD> getProcessIdByName( const std::wstring& processName )
{
	auto szProcessName = processName.c_str();

	HWND hWnd = FindWindowW( nullptr,
		szProcessName );
	if ( !hWnd )
	{
		return std::nullopt;
	}

	DWORD pid;
	GetWindowThreadProcessId( hWnd,
		&pid );
	return pid;
}

std::optional<HANDLE> getProcessHandle( const std::wstring& processName,
	DWORD rights = PROCESS_ALL_ACCESS )
{
	auto pid = getProcessIdByName( processName );
	HANDLE hProc = OpenProcess( rights,
		false,
		*pid );
	if ( !hProc )
	{
		return std::nullopt;
	}
	//listProcessModules( *pid );
	//listProcessThreads( *pid );
	return hProc;
}

bool listProcessModules( DWORD pid )
{
	HANDLE hModuleSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32W moduleEntry;
	// set the size of the structure before using it.
	moduleEntry.dwSize = sizeof( MODULEENTRY32W );

	hModuleSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE,
		pid );
	if ( hModuleSnapshot == INVALID_HANDLE_VALUE )
	{
		return false;
	}

	if ( !Module32FirstW( hModuleSnapshot, &moduleEntry ) )
	{
		CloseHandle( hModuleSnapshot );
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
	} while( Module32NextW( hModuleSnapshot, &moduleEntry ) );

	CloseHandle( hModuleSnapshot );
	return true;
}

bool listProcessThreads( DWORD pid ) 
{ 
	HANDLE hThreadSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 threadEntry;
	// set the size of the structure before using it
	threadEntry.dwSize = sizeof( THREADENTRY32 );

	// take a snapshot of all running threads
	hThreadSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD,
		0 );
	if ( hThreadSnapshot == INVALID_HANDLE_VALUE )
		return false;

	if ( !Thread32First( hThreadSnapshot, &threadEntry ) )
	{
		CloseHandle( hThreadSnapshot );
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
	} while( Thread32Next( hThreadSnapshot, &threadEntry ) );

	CloseHandle( hThreadSnapshot );
	return true;
}

bool listProcesses()
{
	static HANDLE hProc;
	PROCESSENTRY32W processEntry;
	// set the size of the structure before using it
	processEntry.dwSize = sizeof( PROCESSENTRY32W );
	DWORD priority;

	HANDLE hSystemSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS,
		0 );

	if ( hSystemSnapshot == INVALID_HANDLE_VALUE )
	{
		std::cout << "Process snapshot failed\n";
		return false;
	}

	// retrieve information about the first process
	if ( !Process32FirstW( hSystemSnapshot, &processEntry ) )
	{
		// clean the snapshot object
		CloseHandle( hSystemSnapshot );
		return false;
	}

	// enumerate the rest
	while ( Process32NextW( hSystemSnapshot, &processEntry ) )
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

	CloseHandle( hSystemSnapshot );					// clean the snapshot object
	return true;
}

bool setProcessDebugPrivileges( HANDLE hProc )
{
	HANDLE hToken;
	TOKEN_PRIVILEGES newPrivileges;
	LUID luid;

	OpenProcessToken( hProc,
		TOKEN_ADJUST_PRIVILEGES,
		&hToken );
	LookupPrivilegeValueW( nullptr,
		L"seDebugPrivilege",
		&luid );
	newPrivileges.PrivilegeCount = 1;
	newPrivileges.Privileges[0].Luid = luid;
	newPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	int ret = AdjustTokenPrivileges( hToken,
		false,
		&newPrivileges,
		0,
		nullptr,
		nullptr );
	if ( !ret )
	{
		return false;
	}

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

std::optional<HMODULE> getProcessBaseAddress( const std::wstring& windowTitle,
	const std::wstring& exeName )
{
	const auto hProc = getProcessHandle( windowTitle,
		 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION );
	if ( !*hProc )
	{
		return std::nullopt;
	}

	HMODULE hModules[1024];
	DWORD requiredBytes;
	if ( EnumProcessModules( *hProc, hModules, sizeof( hModules ), &requiredBytes ) )
	{
		const DWORD nModules = requiredBytes / sizeof( HMODULE );
		for ( unsigned i = 0; i < nModules; ++i )
		{
			TCHAR szModuleName[MAX_PATH];
			const DWORD nChars = sizeof( szModuleName ) / sizeof( TCHAR );
			if ( GetModuleFileNameEx( *hProc, hModules[i], szModuleName, nChars ) )
			{
				const std::wstring moduleName = szModuleName;
				if ( moduleName.find( exeName ) != std::string::npos )
				{
					return hModules[i];
				}
			}
		}
	}
	return std::nullopt;
}

template<typename T>
T readProcessMemory( HANDLE hProc,
	void* pAddr )
{
	T read;
	std::size_t bytesRead;
	BOOL ret = ReadProcessMemory( hProc,
		pAddr,
		&read,
		sizeof( T ),
		&bytesRead );
	if ( !ret )
	{
		std::cout << "Could not read from the process's memory!\n";
		return 0;
	}
	return read;
}

template<typename T>
std::size_t writeProcessMemory( HANDLE hProc,
	void* pAddr,
	T val )
{
	std::size_t bytesWritten;
	BOOL ret = WriteProcessMemory( hProc,
		pAddr,
		&val,
		sizeof( T ),
		&bytesWritten );
	if ( !ret )
	{
		std::cout << "Could not written to the process's memory!\n";
		return 0;
	}
	return bytesWritten;
}
#pragma endregion

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
	std::cout << *procBaseAddr
		<< '\n';

	std::cout << "getCurrentProcessBaseAddress:"
		<< '\n';
	std::cout << getCurrentProcessBaseAddress()
		<< '\n';
	std::cout << THIS_INSTANCE
		<< '\n';
}


int main()
{
	tests();


	DWORD pAmmo = 0x00e0db44;	// RVA of ammo in COD4
	int readAmmo;
	SIZE_T bytesRead = 0;
	int desiredAmmo;
	SIZE_T bytesWritten = 0;

	std::wstring processName{L"Call of Duty 4"};
	auto szProcessName = processName.c_str();

	std::optional<HANDLE> hProc = getProcessHandle( processName );
	if ( !hProc )
	{
		help();
		return -1;
	}
	std::cout << "We have access.\n";

	// now that we have access to the process you can do whatever you want with it..

	// read and display ammo value every second
	while ( !( GetAsyncKeyState( VK_F10 ) & 1 ) )
	{
		ReadProcessMemory( *hProc,
			(LPVOID)pAmmo,
			&readAmmo,
			sizeof( readAmmo ),
			&bytesRead );
		std::cout << readAmmo
			<< '\n';
		Sleep( 1000 );
	}

	std::cout << "How much ammo do you want?\n";
	std::cin >> desiredAmmo;
	// overwrite the value for funzies
	WriteProcessMemory( *hProc,
		(LPVOID)pAmmo,
		&desiredAmmo,
		sizeof( desiredAmmo ),
		&bytesWritten );

	std::system( "pause" );
	return 0;
}
