#include "ManualMapInject.h"

const char dllFile[] = "C:\\Users\\jacko\\OneDrive\\Documents\\Hackerman\\DLLstuff\\word.dll";
const char targetProcess[] = "Zoom.exe";

int main() {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("CreateTooHelp32Snapshot failed: 0x%X\n", GetLastError());
		system("PAUSE");
		return 0;
	}

	BOOL bReturnecProc = Process32First(hSnap, &PE32);
	DWORD PID = 0;
	while (bReturnecProc) {
		// check target proc then store ID. if not move on loser.
		if (!strcmp(targetProcess, PE32.szExeFile)) {
			PID = PE32.th32ProcessID;
			break;
		}
		bReturnecProc = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);

	if (PID == 0) {
		std::cout << "No process found with that name" << std::endl;
		system("PAUSE");
		return 0;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		printf("Open Process failed: 0x%X\n", GetLastError());
		system("PAUSE");
		return 0;
	}

	if (!ManualMap(hProc, dllFile)) {
		CloseHandle(hProc);
		printf("Unable to inject :( sorry gamer your bad.");
		system("PAUSE");
		return 0;
	}

	else {
		CloseHandle(hProc);
		printf("Mapped Succ. \n");
		return 0;
	}
}