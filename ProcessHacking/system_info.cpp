#include "system_info.h"
#include <winternl.h>
#include <intrin.h>
#include <VersionHelpers.h>
#include "console.h"
#include "assertions_console.h"
#include "utils.h"
#include "os_utils.h"


bool Systeminfo::isProcess64bit( HANDLE handle )
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
		return sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
	}
}

bool Systeminfo::getOsVersionInfo( OSVERSIONINFOEX* pOsInfo )
{
	NTSTATUS ( WINAPI *rtlGetVersion )( LPOSVERSIONINFOEX );
	*(FARPROC*)&rtlGetVersion = GetProcAddress( GetModuleHandleA( "ntdll" ),
		"RtlGetVersion" );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	if ( rtlGetVersion != nullptr )
	{
		// rtlGetVersion returns 0 (STATUS_SUCCESS ) on success
		return rtlGetVersion( pOsInfo ) == 0;
	}
	else
	{
		// GetVersionEx was deprecated in Windows 10
#pragma warning( suppress : 4996 )
		return GetVersionExW( (LPOSVERSIONINFO)pOsInfo );
	}
}

double Systeminfo::getClockSpeed()
{
	DWORD buffSize = MAX_PATH;
	DWORD mhz = MAX_PATH;
	HKEY hKey;

	// open the key where the proc speed is hidden:
	int ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE,
		L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
		0,
		KEY_READ,
		&hKey );
	ASSERT_HRES_REGISTRY_IF_FAILED( ret );

	// query the key
	RegQueryValueExW( hKey,
		L"~MHz",
		nullptr,
		nullptr,
		(LPBYTE) &mhz,
		&buffSize );
	ASSERT_HRES_REGISTRY_IF_FAILED( ret );
	return static_cast<double>( mhz );
}

char* Systeminfo::getVendor()
{
	int regs[4] = {0};
	__cpuid( regs, 0 );					// mov eax,0; cpuid
	memcpy( m_vendor, &regs[1], 4 );		// copy EBX
	memcpy( m_vendor + 4, &regs[3], 4 );	// copy EDX
	memcpy( m_vendor + 8, &regs[2], 4 );	// copy ECX
	m_vendor[12] = '\0';
	printf( "My CPU is a %s\n", m_vendor );
	return m_vendor;
}

int Systeminfo::getFirmwareTypeBiosOrUefi()
{
	FIRMWARE_TYPE ft;
	GetFirmwareType( &ft );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	return ft;
}

std::wstring Systeminfo::getComputerName()
{
	WCHAR buff[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD nSize;
	GetComputerNameW( buff,
		&nSize );
	std::wstring wstr{buff};
	return wstr;
}

float Systeminfo::calculateCpuLoad( unsigned long long idleTicks,
	unsigned long long totalTicks )
{
	static unsigned long long lastTotalTicks{0ui64};
	static unsigned long long lastIdleTicks{0ui64};
	
	unsigned long long totalTicksDiff = totalTicks - lastTotalTicks;
	unsigned long long idleTicksDiff  = idleTicks - lastIdleTicks;
	
	float ret = 1.0f - ( ( totalTicksDiff > 0 ) ?
		static_cast<float>( idleTicksDiff ) / totalTicksDiff :
		0.0f );
	
	lastTotalTicks = totalTicks;
	lastIdleTicks  = idleTicks;
	return ret;
}

float Systeminfo::getCpuUsage()
{
	FILETIME idleTime, kernelTime, userTime;
	int ret = GetSystemTimes( &idleTime,
		&kernelTime,
		&userTime );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );
	if ( !ret )
	{
		return -1;
	}

	return calculateCpuLoad( util::filetimeToInt64( idleTime ),
		util::filetimeToInt64( kernelTime ) + util::filetimeToInt64( userTime ) );
}

bool Systeminfo::isProcessorFeaturePresent( DWORD dwFeature )
{
	return IsProcessorFeaturePresent( dwFeature ) != 0;
}

#if defined _DEBUG && !defined NDEBUG
void Systeminfo::printWindowsVersion()
{
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
}
#endif


Systeminfo::Systeminfo()
	:
	m_sysInfo{},
	m_memoryStatus{}
{
	if ( isProcess64bit( GetCurrentProcess() ) )
	{
		GetSystemInfo( &m_sysInfo );
	}
	else
	{
		GetNativeSystemInfo( &m_sysInfo );
	}
	ASSERT( m_sysInfo.dwPageSize > 0, "Failed to retrieve System Information!" )
	//m_sysInfo.dwProcessorType;			// obsolete
	//m_sysInfo.dwOemId;					// obsolete

	GlobalMemoryStatusEx( &m_memoryStatus );
	HRESULT hres;
	ASSERT_HRES_WIN32_IF_FAILED( hres );
}

Systeminfo::Systeminfo( Systeminfo&& rhs ) noexcept
	:
	m_sysInfo{std::move( rhs.m_sysInfo )},
	m_memoryStatus{std::move( rhs.m_memoryStatus )}
{

}

Systeminfo& Systeminfo::operator=( Systeminfo&& rhs ) noexcept
{
	std::swap( m_sysInfo, rhs.m_sysInfo );
	std::swap( m_memoryStatus, rhs.m_memoryStatus );
	rhs.m_sysInfo = {};
	rhs.m_memoryStatus = {};
	return *this;
}

const WORD Systeminfo::getCpuArchitecture() const noexcept
{
	return m_sysInfo.wProcessorArchitecture;
}

const std::string Systeminfo::getCpuArchitectureStr() const noexcept
{
	std::string architecture = "unknown";
	switch( m_sysInfo.wProcessorArchitecture )
	{
		case PROCESSOR_ARCHITECTURE_AMD64:
			architecture = "x64 (AMD or Intel)";
			break;
		case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
			architecture = "WOW64";
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			architecture = "Intel Itanium Processor Family (IPF)";
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			architecture = "x86";
			break;
		default:
			break;
	}
	return architecture;
}

const DWORD Systeminfo::getPageSize() const noexcept
{
	return m_sysInfo.dwPageSize;
}

const UINT64 Systeminfo::getMinimumAddressAccessibleToApps() const noexcept
{
	return reinterpret_cast<UINT64>( m_sysInfo.lpMinimumApplicationAddress );
}

const UINT64 Systeminfo::getMaximumAddressAccessibleToApps() const noexcept
{
	return reinterpret_cast<UINT64>( m_sysInfo.lpMaximumApplicationAddress );
}

const UINT64 Systeminfo::getCpuMask() const noexcept
{
	return m_sysInfo.dwActiveProcessorMask;
}

const DWORD Systeminfo::getCpuCount() const noexcept
{
	return m_sysInfo.dwNumberOfProcessors;
}

const DWORD Systeminfo::getAllocationGranularity() const noexcept
{
	return m_sysInfo.dwAllocationGranularity;
}

const WORD Systeminfo::getCpuLevel() const noexcept
{
	return m_sysInfo.wProcessorLevel;
}

const WORD Systeminfo::getCpuRevision() const noexcept
{
	return m_sysInfo.wProcessorRevision;
}

const DWORD Systeminfo::getRamPercentUsage() const noexcept
{
	return m_memoryStatus.dwMemoryLoad;
}

const UINT64 Systeminfo::getTotalPhysicalRamInKb() const noexcept
{
	return m_memoryStatus.ullTotalPhys / 1024;
}

const UINT64 Systeminfo::getFreePhysicalRamInKb() const noexcept
{
	return m_memoryStatus.ullAvailPhys / 1024;
}

const UINT64 Systeminfo::getTotalKbOfPagefile() const noexcept
{
	return m_memoryStatus.ullTotalPageFile / 1024;
}

const UINT64 Systeminfo::getFreeKbOfPagefile() const noexcept
{
	return m_memoryStatus.ullAvailPageFile / 1024;
}

const UINT64 Systeminfo::getTotalKbOfVirtualMemory() const noexcept
{
	return m_memoryStatus.ullTotalVirtual / 1024;
}

const UINT64 Systeminfo::getFreeKbOfVirtualMemory() const noexcept
{
	return m_memoryStatus.ullAvailVirtual / 1024;
}
