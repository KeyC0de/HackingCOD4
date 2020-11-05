#include <iostream>
#include <Windows.h>
#include <string>

int main()
{
	DWORD pid;
	DWORD pAmmo = 0x00707A0C;	// absolute address obtained from CE
	int ammo;
	int desiredAmmo = 60;

	HWND hWnd = FindWindow(0, "Call of Duty 4");				// window handle
	GetWindowThreadProcessId(hWnd, &pid);
	//HANDLE handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);	// process handle
	// read + write priviledges:
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hWnd) {
		// read and display ammo value every second
		
		while (true) 
		{
			ReadProcessMemory(handle, (LPVOID)pAmmo, &ammo, sizeof(ammo), 0);
			std::cout << ammo << '\n';
			Sleep(1000);
			std::system("cls");
		}
		
		WriteProcessMemory(handle, (LPVOID)pAmmo, &desiredAmmo, sizeof(desiredAmmo), 0);
	}
	else {
		std::cout << "Window not found\n";
	}

	std::system("Pause");
}


