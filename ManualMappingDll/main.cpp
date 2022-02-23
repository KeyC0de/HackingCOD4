#include "winner.h"

/*
Sometimes manually mapping a dll can be useful as a way that is undetected by anticheat/antidebug
software or countermeasures in the target process.
	Those basically prevent `CreateRemoteThread` that the DLL Injector is using.

API such as LoadLibrary or `CreateRemoteThread` allow the dll to be listed in the loaded module (therefore more easily detectable) by anticheat mechanisms.

and they set PEB.BeingDebugged.

LoadLibrary is just another PE loader.
The goal of manual mapping is recreating the PE loader.
*/

int WINAPI DllMain( HINSTANCE hDll,
	DWORD ulReasonForcall,
	LPVOID pReserved )
{
	switch ( ulReasonForcall )
	{
	case DLL_PROCESS_ATTACH:
	{
		
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		// cleanup..
		FreeLibraryAndExitThread( hDll,
			0u );
	default:
		// Do any cleanup..
		break;
	}
	return TRUE;
}