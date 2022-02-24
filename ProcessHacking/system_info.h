#pragma once

#include "winner.h"
#include <string>


class Systeminfo final
{
	static inline char m_vendor[13];
	SYSTEM_INFO m_sysInfo;
	MEMORYSTATUSEX m_memoryStatus;
public:
	static bool isProcess64bit( HANDLE handle );

	// get OSVERSIONINFO that you can use to query various stuff about the running Windows OS
	// struct _OSVERSIONINFOEXW
	// {
	//	DWORD dwOSVersionInfoSize;
	//	DWORD dwMajorVersion;
	//	DWORD dwMinorVersion;
	//	DWORD dwBuildNumber;
	//	DWORD dwPlatformId;
	//	WCHAR szCSDVersion[128];	// a string indicating the latest Service Pack installed on the system
	//	WORD  wServicePackMajor;	// the major version number of the latest Service Pack installed on the system
	//	WORD  wServicePackMinor;
	//	WORD  wSuiteMask;			// bit mask identifying product suites available
	//	BYTE  wProductType;			// any additional information about the system
	//	BYTE  wReserved;
	// };
	// Uses rtlGetVersion() is available, otherwise falls back to GetVersionEx()
	// returns false if the check fails, true if success
	static bool getOsVersionInfo( OSVERSIONINFOEX* pOsInfo );
	static double getClockSpeed();
	static char* getVendor();
	// returns 1 for BIOS, 2 for UEFI, 0 for Unknown and -1 on error
	static int getFirmwareTypeBiosOrUefi();
	// returns NetBios style computer name
	static std::wstring getComputerName();
	//===================================================
	//	\function	getCpuUsage
	//	\brief  CPU usage is CPU time divided by real time
	//			Note that kernel time also includes the idle time
	//
	//			You'll need to call this at regular intervals, since it measures the load between
	//				the previous call and the current one.
	//
	//			values returned are the sum of the designated times across all CPUs
	//			Returns 1.0f for "CPU fully pinned" or 0.0f for "CPU idle", or somewhere in between.
	//			Returns -1.0 on error.
	//
	//			Multiply the result to get a percentage value
	//
	//			TODO: the function could output skewed or erroneous results on some systems:
	//				if the system spends equal time being idle and used, that is, idle time == (kernel time + user time),
	//	\date	2021/09/21 12:17
	static float getCpuUsage();
	// PF_ARM_64BIT_LOADSTORE_ATOMIC: The 64-bit load/store atomic instructions are available.
	// PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE: The divide instructions are available.
	// PF_ARM_EXTERNAL_CACHE_AVAILABLE: The external cache is available.
	// PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE: The floating-point multiply-accumulate instruction is available.
	// PF_ARM_VFP_32_REGISTERS_AVAILABLE: The VFP/Neon: 32 x 64bit register bank is present. This flag has the same meaning as PF_ARM_VFP_EXTENDED_REGISTERS.
	// PF_3DNOW_INSTRUCTIONS_AVAILABLE: The 3D-Now instruction set is available.
	// PF_CHANNELS_ENABLED : The processor channels are enabled.
	// PF_COMPARE_EXCHANGE_DOUBLE: The atomic compare and exchange operation (cmpxchg) is available.
	// PF_COMPARE_EXCHANGE128: The atomic compare and exchange 128-bit operation (cmpxchg16b) is available.
	//							Windows Server 2003 and Windows XP/2000:  This feature is not supported.
	// PF_COMPARE64_EXCHANGE128: The atomic compare 64 and exchange 128-bit operation (cmp8xchg16) is available.
	//							Windows Server 2003 and Windows XP/2000:  This feature is not supported.
	// PF_FASTFAIL_AVAILABLE: _fastfail() is available.
	// PF_FLOATING_POINT_EMULATED: Floating-point operations are emulated using a software emulator.
	//						This function returns a nonzero value if floating-point operations are emulated; otherwise, it returns zero.
	// PF_FLOATING_POINT_PRECISION_ERRATA: On a Pentium, a floating-point precision error can occur in rare circumstances.
	// PF_MMX_INSTRUCTIONS_AVAILABLE: The MMX instruction set is available.
	// PF_NX_ENABLED: Data execution prevention is enabled.
	//						Windows XP/2000:  This feature is not supported until Windows XP with SP2 and Windows Server 2003 with SP1.
	// PF_PAE_ENABLED: The processor is PAE-enabled. For more information, see Physical Address Extension.
	//					All x64 processors always return a nonzero value for this feature.
	// PF_RDTSC_INSTRUCTION_AVAILABLE: The RDTSC instruction is available.
	// PF_RDWRFSGSBASE_AVAILABLE: RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE instructions are available.
	// PF_SECOND_LEVEL_ADDRESS_TRANSLATION: Second Level Address Translation is supported by the hardware.
	// PF_SSE3_INSTRUCTIONS_AVAILABLE: The SSE3 instruction set is available.
	//						Windows Server 2003 and Windows XP/2000:  This feature is not supported.
	// PF_VIRT_FIRMWARE_ENABLED: Virtualization is enabled in the firmware and made available by the operating system.
	// PF_XMMI_INSTRUCTIONS_AVAILABLE: The SSE instruction set is available.
	// PF_XMMI64_INSTRUCTIONS_AVAILABLE: The SSE2 instruction set is available.
	//						Windows 2000:  This feature is not supported.
	// PF_XSAVE_ENABLED: The processor implements the XSAVE and XRSTOR instructions.
	//						Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP/2000:  This feature is not supported until Windows 7 and Windows Server 2008 R2.
	// PF_ARM_V8_INSTRUCTIONS_AVAILABLE: This ARM processor implements the the ARM v8 instructions set.
	// PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: This ARM processor implements the ARM v8 extra cryptographic instructions (i.e. AES, SHA1 and SHA2).
	// PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: This ARM processor implements the ARM v8 extra CRC32 instructions.
	// PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: This ARM processor implements the ARM v8.1 atomic instructions (e.g. CAS, SWP).
	static bool isProcessorFeaturePresent( DWORD dwFeature );
	static void printWindowsVersion();
private:
	static float calculateCpuLoad( unsigned long long idleTicks,
		unsigned long long totalTicks );
public:
	Systeminfo();
	Systeminfo( const Systeminfo& rhs ) = delete;
	Systeminfo& operator=( const Systeminfo& rhs ) = delete;
	Systeminfo( Systeminfo&& rhs ) noexcept;
	Systeminfo& operator=( Systeminfo&& rhs ) noexcept;

	// PROCESSOR_ARCHITECTURE_ARM64 etc.
	const WORD getCpuArchitecture() const noexcept;
	const std::string getCpuArchitectureStr() const noexcept;
	const DWORD getPageSize() const noexcept;
	const UINT64 getMinimumAddressAccessibleToApps() const noexcept;
	const UINT64 getMaximumAddressAccessibleToApps() const noexcept;
	const UINT64 getCpuMask() const noexcept;
	// get more info using GetLogicalProcessorInformation
	const DWORD getCpuCount() const noexcept;
	// VirtualAlloc allocates memory at 64KB boundaries even though page granularity is 4KB.
	const DWORD getAllocationGranularity() const noexcept;
	const WORD getCpuLevel() const noexcept;
	// for Intel 80386 or 80486 it is a value of the form xxyz.
	// if xx is equal to 0xFF, y - 0xA is the model number, and z is the stepping identifier.
	// if xx is not equal to 0xFF, xx + 'A' is the stepping letter and yz is the minor stepping.
	const WORD getCpuRevision() const noexcept;

	const DWORD getRamPercentUsage() const noexcept;
	const UINT64 getTotalPhysicalRamInKb() const noexcept;
	const UINT64 getFreePhysicalRamInKb() const noexcept;
	const UINT64 getTotalKbOfPagefile() const noexcept;
	const UINT64 getFreeKbOfPagefile() const noexcept;
	const UINT64 getTotalKbOfVirtualMemory() const noexcept;
	const UINT64 getFreeKbOfVirtualMemory() const noexcept;

	// NI adapter info:
	// use GetAdaptersAddresses

	// To get motherboard information you have to use WMI use
	// to initialize wmi:
	// https://docs.microsoft.com/en-us/windows/win32/wmisdk/creating-a-wmi-application-using-c-
	// check classes:
	//	1. Win32_BIOS (bios info)
	//	2. Win32_BaseBoard (motherboard info)
	//	3. Win32_Processor (cpu info)
};