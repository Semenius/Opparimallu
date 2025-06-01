#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cctype>
#include <cstring>

// === Anti-Debugging Technique 1: IsDebuggerPresent ===
bool Detect_IsDebuggerPresent() {
    return IsDebuggerPresent();
}

// === Anti-Debugging Technique 2: PEB BeingDebugged Flag ===
bool Detect_PEBBeingDebugged() {
#ifdef _M_IX86
    return ((*(PBYTE)(__readfsdword(0x30) + 2)) != 0);
#elif _M_X64
    return ((*(PBYTE)(__readgsqword(0x60) + 2)) != 0);
#else
    return false;
#endif
}

// === Anti-Debugging Technique 3: NtQueryInformationProcess (DebugPort) ===
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG
);

bool Detect_DebugPort() {
    DWORD debugPort = 0;
    pNtQueryInformationProcess NtQueryInfo =
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInfo) {
        NtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL);
    }
    return debugPort != 0;
}

// === Substitution Cipher Map (Atbash-style A↔Z, B↔Y...) for lowercase only ===
char substitute(char c) {
    if (c >= 'a' && c <= 'z') {
        return 'z' - (c - 'a'); // Atbash substitution
    }
    return c; // Leave other characters unchanged
}

// === Combined Decryption: Substitution + XOR ===
void RevealMessage() {
    // "flag{GoodbyeFriend}" obfuscated using: 
    // 1. Atbash substitution on lowercase letters
    // 2. XOR with 0x2A
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
        encoded[i] = substitute(encoded[i]); // Reverse Atbash
    }

    std::cout << encoded << std::endl;
}

int main() {
    if (Detect_IsDebuggerPresent()) return 1;
    if (Detect_PEBBeingDebugged()) return 1;
    if (Detect_DebugPort()) return 1;

    RevealMessage(); // Only prints if no debugger is detected
    return 0;
}