#include <iostream>
#include "winner.h"


extern "C" void jmp64( void* );

#if defined _WIN64 || defined __x86_64__ || defined __ppc64__
using TWORD = UINT64;
#elif defined _WIN32
using TWORD = DWORD;
#endif


void directJump( TWORD ip )
{
#if defined _WIN64 || defined __x86_64__ || defined __ppc64__
	jmp64( reinterpret_cast<void*>( ip ) );
#elif defined _WIN32
	__asm {
		jmp ip
	};
#endif
}

void hookedFunction();


uint32_t WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	check(IsProcess64Bit(GetCurrentProcess()));

	//this writes the absolute jump instructions into the memory allocated near the target
	//the E9 jump installed in the target function (GetNum) will jump to here
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return sizeof(absJumpInstructions);
}

uint32_t WriteRelativeJump(void* func2hook, void* jumpTarget, uint8_t numTrailingNOPs)
{
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	int64_t relativeToJumpTarget64 = (int64_t)jumpTarget - ((int64_t)func2hook + 5);
	check(relativeToJumpTarget64 < INT32_MAX);

	int32_t relativeToJumpTarget = (int32_t)relativeToJumpTarget64;

	memcpy(jmpInstruction + 1, &relativeToJumpTarget, 4);

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	uint8_t* byteFunc2Hook = (uint8_t*)func2hook;
	for (int i = 0; i < numTrailingNOPs; ++i)
	{
		memset((void*)(byteFunc2Hook + 5 + i), 0x90, 1);
	}

	return sizeof(jmpInstruction) + numTrailingNOPs;
}



void* AllocPageInTargetProcess(HANDLE process)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	int PAGE_SIZE = sysInfo.dwPageSize;

	void* newPage = VirtualAllocEx(process, NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	return newPage;
}

void* AllocatePageNearAddressRemote(HANDLE handle, void* targetAddr)
{
	check(IsProcess64Bit(handle));

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAllocEx(handle, (void*)highAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAllocEx(handle, (void*)lowAddr, (size_t)PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

void* AllocatePageNearAddress(void* targetAddr)
{
	return AllocatePageNearAddressRemote(GetCurrentProcess(), targetAddr);
}





struct Color
{
	float r;
	float g;
	float b;
};

//since this example is hardcoding the bytes stolen by the hook installed in PrintColorName.
//as such, we won't optimmize it so that the asm is the same in Debug and Release

//when compiled in Debug on v142, Windows SDK 10.0.17763.0
//the first 5 bytes of this function belong to a single instruction
// 48 89 4C 24 08			 mov				 qword ptr[rsp + 8], rcx
#pragma optimize("", off)
__declspec(noinline) void PrintColorName(Color* color)
{
	Color& c = *color;
	if (c.r == c.g && c.r == c.b && c.r == 1.0f) printf("White\n");
	else if (c.r + c.g + c.b == 0.0f) printf("Black\n");
	else if (c.r == c.g && c.r == c.b) printf("Grey\n");
	else if (c.r > c.g && c.r > c.b) printf("Red\n");
	else if (c.g > c.r && c.g > c.b) printf("Green\n");
	else if (c.b > c.r && c.b > c.g) printf("Blue\n");
	else printf("Something Funky\n");
}
#pragma optimize("", on)

void(*PrintColorNameTrampoline)(Color*);
__declspec(noinline) void HookPayload(Color* color)
{
	color->r = 1.0f;
	color->g = 0.0f;
	color->b = 1.0f;
	PrintColorNameTrampoline(color);
}

void WriteTrampoline(void* dst, void* payloadFuncAddr, void* func2hook, uint8_t* stolenBytes, uint32_t numStolenBytes)
{

	//the trampoline consists of the stolen bytes from the target function, following by a jump back
	//to the target function + 5 bytes, in order to continue the execution of that function. This continues like
	//a normal function call
	void* trampolineJumpTarget = ((uint8_t*)func2hook + 5);

	uint8_t* dstIter = (uint8_t*)dst;
	memcpy(dstIter, stolenBytes, numStolenBytes);
	dstIter += numStolenBytes;
	dstIter += WriteAbsoluteJump64(dstIter, trampolineJumpTarget);
}


int trampolineMain()
{
	void(*func2hook)(Color*) = PrintColorName;
	void(*payloadFunc)(Color*) = HookPayload;

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	uint8_t stolenBytes[5];
	memcpy(stolenBytes, func2hook, sizeof(stolenBytes));

	//it makes life way easier when relocating rip-relative operands 
	//if trampolines are located close to the function being hooked
	void* trampolineMemory = AllocatePageNearAddress(func2hook);
	PrintColorNameTrampoline = (void(*)(Color*))trampolineMemory;
	WriteTrampoline(trampolineMemory, HookPayload, func2hook, stolenBytes, sizeof(stolenBytes));

	WriteRelativeJump(func2hook, payloadFunc);

	while (1)
	{
		Color c;
		c.r = (float)rand();
		c.g = (float)rand();
		c.b = (float)rand();
		PrintColorName(&c);
		Sleep(500);
	}
}


/*
void hook( TWORD targetAddress = 0,
	TWORD returnAddress = 0 )
{
#pragma region optionalExtraneous2
	static BYTE previousContents[5];
	TWORD oldProtection;
	// this is optional - I just did it to restore the memory contents
	// of Program.exe on demand
	if ( targetAddress == 0 && returnAddress != 0 )
	{
		*(volatile BYTE*)( targetAddress ) = previousContents[0];
		*(volatile BYTE*)( targetAddress + 1 ) = previousContents[1];
		*(volatile BYTE*)( targetAddress + 2 ) = previousContents[2];
		*(volatile BYTE*)( targetAddress + 3 ) = previousContents[3];
		*(volatile BYTE*)( targetAddress + 4 ) = previousContents[4];

		directJump( returnAddress );	// return to Program.exe - just for fun
	}
#pragma endregion

	VirtualProtect( (void*)targetAddress,
		5,
		PAGE_EXECUTE_READWRITE,
		&oldProtection );

#pragma region optionalExtraneous3
	// safekeep previous memory contents
	previousContents[0] = *(volatile BYTE*)( targetAddress );
	previousContents[1] = *(volatile BYTE*)( targetAddress + 1 );
	previousContents[2] = *(volatile BYTE*)( targetAddress + 2 );
	previousContents[3] = *(volatile BYTE*)( targetAddress + 3 );
	previousContents[4] = *(volatile BYTE*)( targetAddress + 4 );
#pragma endregion

	*(volatile BYTE*)(targetAddress) = 0xE9;	// write the JMP opcode
	*(volatile TWORD*)(targetAddress + 1) = (TWORD)&hookedFunction - ( targetAddress + 5 );	// write the RVA to jump to
	// jmp @hookedFunction

	// restore page to its former status
	VirtualProtect( (void*)targetAddress,
		5,
		oldProtection,
		nullptr );
}


void hookedFunction()
{
	while ( true )
	{
		std::cout << "Instead of adding we print this!\n";
		if ( GetAsyncKeyState( VK_F10 ) & 1 )
		{
			std::cout << "Return Program.exe to previous state\n";
			hook( 0x011F10E5,
				0x011F1010 );
		}
		Sleep( 3000 );
	}
}
*/

// a 32 bit hooking function
void hook(void* targetFunc, void* hookedFunc)
{
	DWORD oldProtect;
	VirtualProtect(AddColors, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	
	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	
	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the payload function and the instruction immediately AFTER the jmp instruction
	const uint32_t relAddr = (uint32_t)hookedFunc - ((uint32_t)targetFunc + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(targetFunc, jmpInstruction, sizeof(jmpInstruction));
}

// in 64 bit things are a bit trickier, because functions can be located so far away from
//	each other than a 32 bit jump instruction can't jump that far.
// There’s no such thing as a 64 bit relative jmp instruction, so the next best option is
//	to jmp to an address stored in a register
// eg.
// mov r10, 400h	; r10 is volatile register not used by default on function calls so it's ideal
// jmp r10
// 
// If we throw this in the beginning of our targetFunction instead of the 5 byte jump from
//	before, we’d limit the number of functions that we could hook to those with 13 or more
//	bytes. That’s a significantly bigger limitation than our 32 bit code, so we’re instead
//	going to write the bytes for this absolute jump somewhere in memory that’s close to the
//	function we’re hooking. Then we’ll have the 5 byte jump we install in that function
//	jump to this absolute jump, instead of straight to the payload function.
// This intermediate function is known as the relay function.
// Then the relay function will jump to our hookedFunction
// Then the hookedFunction will do its work and will jump to our trampoline
// Finally the trampoline will jump to the targetFunction's body
//
// What we need to do to make a trampoline is copy the first 5 bytes to a buffer
//	before we overwrite them with our hook.
// In the easy case those 5 bytes would contain whole instructions.
// But in most cases in the real world this won't be the case.
// We're going to have to get our hands dirty.
// We're going to need to steal 5 or more bytes (rounded up to the nearest whole
//	instruction) of this function instead of the first 5B, such that we can execute whole
//	instructions in our trampoline.
// If those bytes contain jmp/call instructions or other rip-relative instructions
//	(like like lea rcx,[rip+0xbeef]) then we have to reconstruct their addresses
// We refer to this as the absolute instruction table (AIT).
//	For each relative jump or call instruction, calculate the address that it originally intended to reference, and add an absolute jmp/call to that address in the Absolute Instruction Table.
// Rewrite the relative instructions in the stolen bytes to jump to their corresponding entry in the Absolute Instruction Table.
// Finally jump back to the next byte of the targetFunction's body.
//
// Note that we're going to build our trampoline function in the same "near" memory that
//	the relay function is currently being constructed in.
//
// The verb “steal” is important here - we’re not only going to copy these instruction bytes, we’re also going to replace them with 1 byte NOPs in the target function. That way won’t wind up with any partial instructions when we install the hook jump.
// 
// To make sure we steal whole instructions, we need to use a disassembly library.
// We'll use the Capstone library.
// Capstone will help us detect whether a whole instruction is rip relative or a jmp/call instruction.
// Then we relocateInstruction
// 
//
// AllocatePageNearAddress finds memory close to the target function to allocate our relay
//	function. Then we do:
void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
  uint8_t absJumpInstructions[] = 
  { 
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r10, addr
	0x41, 0xFF, 0xE2 //jmp r10
  }; 

  uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
  memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
  memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}

void InstallHook(void* func2hook, void* payloadFunction)
{
	void* relayFuncMemory = AllocatePageNearAddress(func2hook);
	WriteAbsoluteJump64(relayFuncMemory, payloadFunction); //write relay func instructions

	//now that the relay function is built, we need to install the E9 jump into the target func,
	//this will jump to the relay function
	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)func2hook + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
}

// That is all we need to know to hook functions in x32/x64 that we have source access to
// But what about running programs? Read on..
// 
// The easiest way to infiltrate a running program that we don't have source access, is to
//	inject a dll to it. And we need to do some extra work to get a pointer to
//	our targetFunction
// What we’re after is the relative virtual address (RVA) of the beginning of this function.
// So we gotta use a debugger. x64dbg is ideal.
//	Find the symbols it's importing
//	put a breakpoint in one of them depending on what you wanna do
//	RMB on the address & Copy -> RVA
// Since programs (and individual modules, thanks to ASLR) can be loaded into memory at different locations across multiple runs of the same program, having the RVA of a function means that we can reliably get that function’s address, no matter where the process is loaded in memory.
// If our targetFunction is not imported from a dll then it is implemented inside the base
//	module of the process. To find the address of the base module "myModule" is equivalent
//	to finding the base address of the process "myModule.exe".
// so targetFunction = (void*)( getModuleBaseAddress() + RVA )
// 
// Add instructions to the AIT is not enough.
// We also have to rewrite the stolen instruction. This needs to be handled differently
//	for jumps & calls
//
// 
//
// What if the instruction is a loop?
// To be delayed. Not handling loops for now.



int WINAPI DllMain( HINSTANCE hDll,
	DWORD ulReasonForcall,
	LPVOID pReserved )
{
	switch ( ulReasonForcall )
	{
	case DLL_PROCESS_ATTACH:
	{
		hook( 0x011F10E5 );
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
	{
		// dll cleanup must be done from code that loaded the dll,
		//	as if by FreeLibraryAndExitThread( hDll, 0u );
		// If the dll itself called LoadLibrary then it can unload itself like so:
		// GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		// 	(LPCTSTR)DllMain,
		// 	&hDll );
		// FreeLibraryAndExitThread( hDll,
		// 	0u );
	}
	}
	return TRUE;
}


// acknowledgements: http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
