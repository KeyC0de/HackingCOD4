#include "winner.h"

// The Interval, a pointer to a 64 bit integer, is somewhat 2 sided.
// If it is negative it specifies the relative time to sleep (in units of 100ns).
//	if not it specifies the absolute time to wake up.
using TZwDelayExecution = DWORD( __stdcall * )( int alertable, __int64* interval );



//// get a handle to the DLL module.
//HMODULE hLib = LoadLibraryW(TEXT("ntdll")); 
//// get the pointer to the function
//TZwDelayExecution zwDelayExecution = (TZwDelayExecution) GetProcAddress( hLib,
//	"ZwDelayExecution" );
