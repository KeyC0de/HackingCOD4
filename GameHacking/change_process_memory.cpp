#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

#pragma region convenientWrappers
static HANDLE g_hProcess;

bool findProcessByName( char* processName )
{
	PROCESSENTRY32 processEntry;
	ZeroMemory( &processEntry, sizeof( PROCESSENTRY32 ) );
	processEntry.dwSize = sizeof( PROCESSENTRY32 );

	HANDLE hSystemSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS,
		0 );

	if ( hSystemSnapshot == INVALID_HANDLE_VALUE )
	{
		std::cout << "Process snapshot failed" << '\n';
		return false;
	}

	while ( Process32Next( hSystemSnapshot, &processEntry ) )
	{
		std::cout << processEntry.szExeFile << '\n';

		if ( !strcmp( processName, processEntry.szExeFile ) )
		{
			std::cout << "Found process "
				<< processEntry.szExeFile
				<< " with process ID "
				<< processEntry.th32ProcessID
				<< '\n';
			
			g_hProcess = OpenProcess( PROCESS_ALL_ACCESS,
				false,
				processEntry.th32ProcessID );
			if ( !g_hProcess )
			{
				std::cout << "Failed to get process handle" << '\n';
			}

			CloseHandle( hSystemSnapshot );
			return true;
		}
	}

	std::cout << "Couldn't find " << processName << " in the process list.\n";
	return false;
}

template<typename T>
BOOL writeProcessMemory( HANDLE hProcess, void* address, T val )
{
	std::size_t bytesWritten;
	BOOL ret = WriteProcessMemory( hProcess,
		address,
		&val,
		sizeof( T ),
		&bytesWritten );
	if ( !ret )
	{
		std::cout << "Could not written to the process's memory!" << '\n';
		return 0;
	}
	return bytesWritten;
}

template<typename T>
T readProcessMemory( HANDLE hProcess, void* address )
{
	T read;
	std::size_t bytesRead;
	BOOL ret = ReadProcessMemory( hProcess,
		address,
		&read,
		sizeof( T ),
		&bytesRead );
	if ( !ret )
	{
		std::cout << "Could not read from the process's memory!" << '\n';
		return 0;
	}
	return read;
}
#pragma endregion


int main()
{
	DWORD pid;
	DWORD pAmmo = 0x00707A0C;	// address of ammo in COD4 - obtained from CE
	int ammo;
	int desiredAmmo = 60;

	std::string processName = "Call of Duty 4";
	HWND hWnd = FindWindowA( nullptr,
		processName.c_str() );
	if ( !hWnd )
	{
		std::cout << L"Window not found" << L'\n';
		return -1;
	}

	GetWindowThreadProcessId( hWnd,
		&pid );
	std::cout << "pid=" << pid << '\n';

	//HANDLE handle = OpenProcess( PROCESS_VM_READ,
	//	FALSE,
	//	pid );
	// give all priviledges for the target process:
	HANDLE hProc = OpenProcess( PROCESS_ALL_ACCESS,
		FALSE,
		pid );

	if ( hProc )
	{
		// read and display ammo value every second
		while ( true )
		{
			ReadProcessMemory( hProc,
				(LPVOID)pAmmo,
				&ammo,
				sizeof( ammo ),
				nullptr );
			std::cout << ammo << '\n';
			Sleep( 1000 );
		}
		// or comment the above and just use this:
		WriteProcessMemory( hProc,
			(LPVOID)pAmmo,
			&desiredAmmo,
			sizeof( desiredAmmo ),
			nullptr );
	}
	else
	{
		std::cout << "Process could not be opened.\n";
		return -2;
	}

	std::cout << "Done\n";
	std::system( "pause" );
	return 0;
}
