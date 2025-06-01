#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <iostream>

//https://unprotect.it/snippet/detecting-virtual-environment-process/228/

bool DetectVirtualEnvironmentProcess() {
    // List of common virtual environment process names
    std::vector<std::wstring> virtualProcesses = {
        L"VMwareService.exe",
        L"VMwareTray.exe", 
        L"TPAutoConnSvc.exe",
        L"VMtoolsd.exe",
        L"VMwareuser.exe",
        // VirtualBox specific processes
        L"VBoxService.exe",
        L"VBoxTray.exe"
    };

    // Create snapshot of current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Get first process
    if (!Process32FirstW(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return false;
    }

    // Iterate through all processes
    do {
        for (const auto& virtualProcess : virtualProcesses) {
            // Case insensitive comparison of process names
            if (_wcsicmp(pe32.szExeFile, virtualProcess.c_str()) == 0) {
                std::wcout << L"Virtual environment process detected: " << pe32.szExeFile << std::endl;
                CloseHandle(hProcessSnap);
                return true;
            }
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return false;
}

int main() {
    if (DetectVirtualEnvironmentProcess()) {
        std::cout << "Running in a virtual environment!" << std::endl;
    } else {
        std::cout << "No virtual environment detected." << std::endl;
    }
    return 0;
}