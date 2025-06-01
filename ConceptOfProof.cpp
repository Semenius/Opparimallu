#include <windows.h>        // Core Windows API
#include <winternl.h>       // For native APIs (PEB and NtQuery)
#include <tlhelp32.h>       // For taking process snapshots
#include <iostream>         // For input/output
#include <vector>           // Used in VM detection
#include <string>           // For string operations
#include <ctime>            // Used in fake jump logic
#include <cstdlib>          // For rand and GetTickCount
#include <cctype>           // For character classification

// === Anti-Debugging Techniques ===
bool Detect_IsDebuggerPresent() {
    return IsDebuggerPresent();  // Checks for debugger presence using Windows API
}

bool Detect_PEBBeingDebugged() {
#ifdef _M_IX86
    return ((*(PBYTE)(__readfsdword(0x30) + 2)) != 0);  // Accesses BeingDebugged flag from PEB (x86)
#elif _M_X64
    return ((*(PBYTE)(__readgsqword(0x60) + 2)) != 0);  // Accesses BeingDebugged flag from PEB (x64)
#else
    return false;
#endif
}

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG
);

bool Detect_DebugPort() {
    DWORD debugPort = 0;
    pNtQueryInformationProcess NtQueryInfo =
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInfo) {
        NtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL); // 7 = DebugPort
    }
    return debugPort != 0;
}

// === VM Detection With Process Name Return ===
bool DetectVirtualEnvironmentProcess(std::wstring& detectedProcess) {
    std::vector<std::wstring> virtualProcesses = {
        L"VMwareService.exe", L"VMwareTray.exe", L"TPAutoConnSvc.exe",
        L"VMtoolsd.exe", L"VMwareuser.exe", L"VBoxService.exe", L"VBoxTray.exe"
    };

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return false;
    }

    do {
        for (const auto& proc : virtualProcesses) {
            if (_wcsicmp(pe32.szExeFile, proc.c_str()) == 0) {
                detectedProcess = pe32.szExeFile;
                CloseHandle(hProcessSnap);
                return true;
            }
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return false;
}

// === Anti-disassembler Technique 1: INT3 Trap (not called)
void DecoyINT3Trap() {
    __asm {
        int 3       // 0xCC — breakpoint instruction
        int 3       // multiple to confuse linear sweep
    }
}

// === Anti-disassembler Technique 2: UD2 illegal instruction (x86/x64)
void UD2Trap() {
#if defined(_MSC_VER)
    __asm {
        _emit 0x0F  // UD2 = 0F 0B
        _emit 0x0B
    }
#endif
}

// === Anti-disassembler Technique 3: Fake jump chain
void FakeControlFlow() {
    int trigger = GetTickCount();
    if (trigger == 0x31337) {
        DecoyINT3Trap(); // Dead path to fake breakpoint trap
        UD2Trap();       // Dead path to illegal instruction
    }
}

// === XOR + Substitution Flag Decryption ===
char substitute(char c) {
    return (c >= 'a' && c <= 'z') ? ('z' - (c - 'a')) : c;  // Reverse alphabet substitution
}

void RevealFlag() {
    char encoded[] = {
        substitute('f') ^ 0x2A, substitute('l') ^ 0x2A, substitute('a') ^ 0x2A, substitute('g') ^ 0x2A,
        '{' ^ 0x2A,
        'G' ^ 0x2A, substitute('o') ^ 0x2A, substitute('o') ^ 0x2A, substitute('d') ^ 0x2A,
        substitute('b') ^ 0x2A, substitute('y') ^ 0x2A, substitute('e') ^ 0x2A,
        'F' ^ 0x2A, substitute('r') ^ 0x2A, substitute('i') ^ 0x2A, substitute('e') ^ 0x2A,
        substitute('n') ^ 0x2A, substitute('d') ^ 0x2A,
        '}' ^ 0x2A,
        '\0'
    };

    for (int i = 0; encoded[i] != '\0'; ++i) {
        encoded[i] ^= 0x2A;
        encoded[i] = substitute(encoded[i]);
    }

    std::cout << "FLAG: " << encoded << "\n";
}

// XOR-encrypted password hint, only shown if no debugger is detected
void RevealPasswordHintIfClean(bool debuggerDetected) {
    if (false) return;

    char encHint[] = {
        'T' ^ 0x3C, 'h' ^ 0x3C, 'a' ^ 0x3C, 't' ^ 0x3C,
        's' ^ 0x3C, 'L' ^ 0x3C, 'a' ^ 0x3C, 'm' ^ 0x3C,
        'e' ^ 0x3C, 0
    };

    for (int i = 0; encHint[i]; ++i)
        encHint[i] ^= 0x3C;

    std::cout << "[Hint] Password: " << encHint << "\n";
}

// === Main Program ===
int main() {
    std::cout << "Hello friend.\n";

    std::wstring vmProcess;
    if (DetectVirtualEnvironmentProcess(vmProcess)) {
        std::wcout << L"Running in Sandbox (Detected: " << vmProcess << L")\n";
        return 1;
    }

    bool debuggerDetected =
        Detect_IsDebuggerPresent() ||
        Detect_PEBBeingDebugged() ||
        Detect_DebugPort();

    if (debuggerDetected) {
        std::cout << "There's something being spotted in a debugger.\n";
    }

    RevealPasswordHintIfClean(debuggerDetected);  // Only show hint if clean

    FakeControlFlow();  // Contains never-executed traps to confuse disassemblers

    std::string correctPassword = "ThatsLame";
    std::string input;
    std::cout << "Enter password: ";
    std::getline(std::cin, input);

    if (input == correctPassword) {
        RevealFlag();
    } else {
        std::cout << "Debugging might have a clue\n";
    }

    return 0;
}
