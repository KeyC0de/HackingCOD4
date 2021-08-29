#include "Windows.h"
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <optional>
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

std::optional<HANDLE> accessProcess( const std::wstring& processName )
{
	auto pid = getProcessIdByName( processName );
	HANDLE hProc = OpenProcess( PROCESS_ALL_ACCESS,
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
		std::cout << "\n\nmodule name = " << moduleEntry.szModule;
		std::cout << "\nexe path = " << moduleEntry.szExePath;
		std::cout << "\npid = " << moduleEntry.th32ProcessID;
		std::cout << "\nRef count (g) = " << moduleEntry.GlblcntUsage;
		std::cout << "\nRef count (p) = " << moduleEntry.ProccntUsage;
		//std::cout << "\nBase address = " << moduleEntry.modBaseAddr;
		std::cout << "\nBase size = " << moduleEntry.modBaseSize;
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
			std::cout << "\n\nthread id = " << threadEntry.th32ThreadID;
			std::cout << "\nbase priority = " << threadEntry.tpBasePri;
			std::cout << "\ndelta priority = " << threadEntry.tpDeltaPri;
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
		std::cout << "\n\nprocess name = " << processEntry.szExeFile;
		std::cout << "\npid = " << processEntry.th32ProcessID;
		std::cout << "\nthread count = " << processEntry.cntThreads;
		std::cout << "\nparent's pid = " << processEntry.th32ParentProcessID;
		std::cout << "\npriority base = " << processEntry.pcPriClassBase;
		priority = GetPriorityClass( hProc );
		if ( priority )
		{
			std::cout << "\npriority = " << priority;
		}
	}

	CloseHandle( hSystemSnapshot );					// clean the snapshot object
	return true;
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


int main()
{
	DWORD pAmmo = 0x00e0db44;	// RVA of ammo in COD4
	int readAmmo;
	SIZE_T bytesRead = 0;
	int desiredAmmo;
	SIZE_T bytesWritten = 0;

	std::wstring processName{L"Call of Duty 4"};
	auto szProcessName = processName.c_str();

	std::optional<HANDLE> hProc = accessProcess( processName );
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
