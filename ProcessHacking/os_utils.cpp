#include "os_utils.h"
#include "utils.h"
#include "assertions_console.h"
#include <fstream>
#include <VersionHelpers.h>
#include <psapi.h>
#include <thread>

#pragma comment( lib, "psapi.lib" )


namespace util
{


std::string printHresultErrorDescription( HRESULT hres )
{
	_com_error error{hres};
	return util::ws2s( error.ErrorMessage() );
}

std::wstring printHresultErrorDescriptionW( HRESULT hres )
{
	_com_error error{hres};
	return error.ErrorMessage();
}

std::string getLastErrorAsString()
{
	// get the error message, if any
	DWORD errorMsgId = ::GetLastError();
	if ( errorMsgId == 0 )
	{
		return std::string{""};
	}

	LPSTR buff = nullptr;
	size_t messageLength = FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		errorMsgId,
		MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
		(LPSTR)&buff,
		0,
		nullptr );

	std::string message( buff,
		messageLength );
	LocalFree( buff );
	return message;
}

void getSystemVersion()
{
#if defined _DEBUG && !defined NDEBUG
	KeyConsole& console = KeyConsole::getInstance();
	using namespace std::string_literals;
	if ( IsWindowsXPOrGreater() )
	{
		console.print( "XPOrGreater\n"s );
	}

	if ( IsWindowsXPSP1OrGreater() )
	{
		console.print( "XPSP1OrGreater\n"s );
	}

	if ( IsWindowsXPSP2OrGreater() )
	{
		console.print( "XPSP2OrGreater\n"s );
	}

	if ( IsWindowsXPSP3OrGreater() )
	{
		console.print( "XPSP3OrGreater\n"s );
	}

	if ( IsWindowsVistaOrGreater() )
	{
		console.print( "VistaOrGreater\n"s );
	}

	if ( IsWindowsVistaSP1OrGreater() )
	{
		console.print( "VistaSP1OrGreater\n"s );
	}

	if ( IsWindowsVistaSP2OrGreater() )
	{
		console.print( "VistaSP2OrGreater\n"s );
	}

	if ( IsWindows7OrGreater() )
	{
		console.print( "Windows7OrGreater\n"s );
	}

	if ( IsWindows7SP1OrGreater() )
	{
		console.print( "Windows7SP1OrGreater\n"s );
	}

	if ( IsWindows8OrGreater() )
	{
		console.print( "Windows8OrGreater\n"s );
	}

	if ( IsWindows8Point1OrGreater() )
	{
		console.print( "Windows8Point1OrGreater\n"s );
	}

	if ( IsWindows10OrGreater() )
	{
		console.print( "Windows10OrGreater\n"s );
	}

	if ( IsWindowsServer() )
	{
		console.print( "Server Machine.\n"s );
	}
	else
	{
		console.print( "Client Machine.\n"s );
	}
#endif
}

int32_t fileExistsWin32( const std::string& path )
{
	uint32_t attribs = GetFileAttributesW( s2ws( path ).data() );
	return ( attribs != INVALID_FILE_ATTRIBUTES
		&& !( attribs & FILE_ATTRIBUTE_DIRECTORY ) );
}

int getCpuCount()
{
#ifdef _WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );
	return sysinfo.dwNumberOfProcessors;
#elif defined __linux__
	return sysconf( _SC_NPROCESSORS_ONLN );
#endif
}

//===================================================
//	\function	getPeb
//	\brief  Process & Thread Environment Block
//			https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
//	\date	2021/08/29 1:05
PPEB getPeb()
{
	// Process Environment Block (TEB)
	static PPEB pPeb;
	// Thread Environment Block (TEB)
	PTEB pTeb;
#if defined _WIN64 || defined _M_X64
	pTeb = reinterpret_cast<PTEB>( __readgsqword( reinterpret_cast<DWORD_PTR>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#else
	pTeb = reinterpret_cast<PTEB>( __readfsdword( reinterpret_cast<DWORD_PTR>( &static_cast<NT_TIB*>( nullptr )->Self ) ) );
#endif

	// Process Environment Block (PEB)
	pPeb = pTeb->ProcessEnvironmentBlock;
	return pPeb;
}

HMODULE getProcess( DWORD processId,
	char* processName )
{
	char szTestedProcessName[MAX_PATH] = "<unknown>";

	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		processId );

	HMODULE hModule;
	if ( hProcess != nullptr)
	{
		DWORD cbNeeded;

		if ( EnumProcessModulesEx( hProcess,
			&hModule,
			sizeof( hModule ),
			&cbNeeded,
			LIST_MODULES_32BIT | LIST_MODULES_64BIT ) )
		{
			GetModuleBaseName( hProcess,
				hModule,
				util::s2ws( szTestedProcessName ).data(),
				sizeof( szTestedProcessName ) / sizeof( char ) );
			if ( !_stricmp( processName, szTestedProcessName ) )
			{
				CloseHandle( hProcess );
				return hModule;
			}
		}
	}
	CloseHandle( hProcess );
	return nullptr;
}

HWND getWindow( const std::string& name )
{
	return FindWindowW( nullptr,
		s2ws( name ).data() );
}

std::wstring bstrToStr( const BSTR& bstr )
{
	ASSERT( bstr != nullptr, "BSTR was null!" );
	std::wstring str{bstr, SysStringLen( bstr )};	// takes ownership so no need to SysFreeString
	return str;
}

#pragma warning( disable : 4267 )
BSTR strToBstr( const std::wstring& str )
{
	ASSERT( !str.empty(), "String was null!" );
	BSTR bstr = SysAllocStringLen( str.data(),
		str.size() );
	return bstr;
}
#pragma warning( default : 4267 )

bool isFileBinary( const char* fname )
{
	char c;
	std::ifstream ifs{fname, std::ios::binary};
	unsigned charsRead = 0;
	while ( ( c = ifs.get() ) != EOF && charsRead < 255 )
	{
		if ( c == '\0' )
		{
			return true;
		}
		++charsRead;
	}
	return false;
}

#if defined _DEBUG && !defined NDEBUG
bool printFile( const char* fname )
{
	std::ifstream ifs{fname};
	KeyConsole& console = KeyConsole::getInstance();
	if ( !ifs.is_open() )
	{
		console.log( "can't open " + std::string{*fname} + "!\n" );
		return false;
	}
	char c;
	while ( !ifs.eof() )
	{
		c = ifs.get();
		console.print( std::string{c} );
	}
	return true;
}
#endif

void pinThreadToCore( HANDLE hThread,
	DWORD core )
{
	// a set bit represents a CPU core
	DWORD_PTR mask = ( static_cast<DWORD_PTR>( 1 ) << core );
	auto ret = SetThreadAffinityMask( GetCurrentThread(),
		mask );
}

static std::vector<HANDLE> g_detachedThreads;

void setupDetachedThreadsVector( unsigned nThreads )
{
	g_detachedThreads.reserve( nThreads );
}

void terminateDetachedThreads()
{
#if defined _DEBUG && !defined NDEBUG
	KeyConsole& console = KeyConsole::getInstance();
	console.print( "Clearing up detached threads\n" );
#endif
	for ( const auto th : g_detachedThreads )
	{
		DWORD exitCode;
		int ret;
		HRESULT hres;
		ret = GetExitCodeThread( th,
				&exitCode );
		ASSERT_HRES_WIN32_IF_FAILED( hres );

		ret = TerminateThread( th,
			exitCode );
		ASSERT_HRES_WIN32_IF_FAILED( hres );
	}
}

//===================================================
//	\function	doPeriodically
//	\brief  like a timer event
//			executes void(*f)() function at periodic (ms) intervals
//	\date	2021/09/06 1:05
void doPeriodically( const std::function<void(void)>& f,
	size_t intervalMs,
	bool now )
{
	std::thread t{[f, intervalMs, now] () -> void
		{
			if ( now )
			{
				while ( true )
				{
					f();
					auto chronoInterval = std::chrono::milliseconds( intervalMs );
					std::this_thread::sleep_for( chronoInterval );
				}
			}
			else
			{
				while ( true )
				{
					auto chronoInterval = std::chrono::milliseconds( intervalMs );
					std::this_thread::sleep_for( chronoInterval );
					f();
				}
			}
		}
	};
	g_detachedThreads.push_back( t.native_handle() );
	t.detach();
}

void doAfter( const std::function<void(void)>& f,
	size_t intervalMs )
{
	std::thread t{[f, intervalMs] () -> void
		{
			auto chronoInterval = std::chrono::milliseconds( intervalMs );
			std::this_thread::sleep_for( chronoInterval );
			f();
		}
	};
	g_detachedThreads.push_back( t.native_handle() );
	t.detach();
}

// advanced Windows 32 base API DLL file that supports security and registry calls
#pragma comment( lib, "advapi32.lib" )
std::optional<DWORD> registryGetDword( HKEY hKey,
	const std::wstring& regName )
{
	DWORD bufferSize = sizeof( DWORD );
	DWORD val = 0ul;
	long ret = RegQueryValueExW( hKey,
		regName.c_str(),
		nullptr,
		nullptr,
		reinterpret_cast<LPBYTE>( &val ),
		&bufferSize );
	if ( ret != ERROR_SUCCESS )
	{
		return std::nullopt;
	}
	return val;
}

std::optional<std::wstring> registryGetString( HKEY hKey,
	const std::wstring& regName )
{
	wchar_t buffer[512];
	DWORD bufferSize = sizeof( buffer );
	long ret = RegQueryValueExW( hKey,
		regName.c_str(),
		nullptr,
		nullptr,
		reinterpret_cast<LPBYTE>( buffer ),
		&bufferSize );
	if ( ret != ERROR_SUCCESS )
	{
		return std::nullopt;
	}
	std::wstring str{std::begin( buffer ), std::end( buffer )};
	return str;
}


}// namespace util