#pragma once

#include <iostream>
#include "winner.h"
#include <TlHelp32.h>
#include <psapi.h>


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

DWORD findPattern( const char* szModuleName,
	const char* pattern,
	const char* szMask,
	DWORD patternLen )
{
	MODULEINFO moduleInfo = getModuleInfo( szModuleName );
	DWORD baseAddress = reinterpret_cast<DWORD>( moduleInfo.lpBaseOfDll );
	DWORD imageSize = moduleInfo.SizeOfImage;

	DWORD iEnd = imageSize - patternLen;
	for ( DWORD i = 0; i < iEnd; ++i )
	{
		bool bFound = true;
		for ( DWORD j = 0; j < patternLen; ++j )
		{
			bFound &= szMask[j] == '?' || pattern[j] == *reinterpret_cast<char*>( baseAddress + i + j );
		}
		if ( bFound )
		{
			return baseAddress + i;
		}
	}

	return 0xDeadBeef;
}


bool sigScan( const std::string& exeName,
	const std::string& signature,
	const std::string& mask )
{
	auto szModuleName = exeName.c_str();
	auto szSignature = signature.c_str();
	auto szMask = mask.c_str();
	int patternLen = mask.length();
	//ASSERT( patternLen > 0)
	DWORD desiredAddr = findPattern( szModuleName,
		szSignature,
		szMask,
		patternLen );
	if ( desiredAddr == 0xDeadBeef )
	{
		MessageBoxA( nullptr,
			"Signature not found in module.",
			"Failure!",
			MB_OK );
		return false;
	}
	// found signature
	//char szBuffText[1024];
	//sprintf( szBuffText,
	//	"Found signature! in module %s\n\bat address dw: %02x", szModuleName, desiredAddr );
	//MessageBoxA( nullptr,
	//	szBuffText,
	//	"Success!",
	//	MB_OK );

	// now write desired value to that memory location - nops
	char* replacedOpcode = new char[patternLen];
	for ( USHORT i = 0; i < patternLen; ++i )
	{
		strcat( replacedOpcode, "\x90" );
	}
	// must look like this "\x90\x90\x90\x90\x90\x90\x90";
	memcpyProtectedMemory( reinterpret_cast<void*>( desiredAddr ),
		replacedOpcode,
		patternLen );
	delete[] replacedOpcode;
	return true;
}


int WINAPI DllMain( HINSTANCE hInst,
	DWORD ulReasonForcall,
	LPVOID pReserved )
{
	switch ( ulReasonForcall )
	{
	case DLL_PROCESS_ATTACH:
		{
		bool bResult = false;
		//MessageBoxA( nullptr,
		//	"dll attached to thread.",
		//	"Attached",
		//	MB_OK );
		bResult = sigScan( "iw3sp.exe",
			"\x89\x94\xB8\x00\x00\x00\x00",
			"xxx????" );
		if ( bResult )
		{
			MessageBoxA( nullptr,
				"Replaced opcode!",
				"Success!",
				MB_ICONINFORMATION | MB_OK );
		}
		else
		{
			MessageBoxA( nullptr,
				"Something went amiss.",
				"Failure!",
				MB_ICONERROR | MB_OK );
		}
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
	default:
		break;
	}
	return TRUE;
}
