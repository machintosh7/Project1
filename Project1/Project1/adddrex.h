#pragma once

#ifndef ADDREX_H
#define ADDREX_H

#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>

using namespace std;

template <class T>
const T Read(const HANDLE handle, const std::uintptr_t address) noexcept {
    T value{};
    ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), NULL);
    return value;
}

template <typename T>
bool Write(const HANDLE handle, const std::uintptr_t address, const T& value) noexcept {
    return WriteProcessMemory(handle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), NULL) != 0;
}

string processName;

// Inject DLL function
inline void inject(const HANDLE processHandle, const char* dllPath) {
    DWORD processId;

    GetWindowThreadProcessId(FindWindowA(NULL, processName.c_str()), &processId);

    LPVOID remoteString = VirtualAllocEx(processHandle, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
    if (remoteString == NULL) {
        std::cerr << "Erreur : Impossible d'allouer de l'espace dans le processus cible." << std::endl;
        return;
    }

    if (!Write(processHandle, reinterpret_cast<std::uintptr_t>(remoteString), dllPath)) {
        std::cerr << "Erreur : Impossible d'écrire le chemin de la DLL dans le processus cible." << std::endl;
        VirtualFreeEx(processHandle, remoteString, 0, MEM_RELEASE);
        return;
    }

    LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Erreur : Impossible d'obtenir l'adresse de LoadLibraryA dans le processus cible." << std::endl;
        VirtualFreeEx(processHandle, remoteString, 0, MEM_RELEASE);
        return;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr), remoteString, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "Erreur : Impossible de créer un thread distant dans le processus cible." << std::endl;
        VirtualFreeEx(processHandle, remoteString, 0, MEM_RELEASE);
        return;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    std::cout << "DLL injectée avec succès." << std::endl;

    CloseHandle(remoteThread);
    VirtualFreeEx(processHandle, remoteString, 0, MEM_RELEASE);
    CloseHandle(processHandle);
}

inline HANDLE GetProcessHandleFromName(const std::string& processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        do {
            std::wstring wideProcessName(processName.begin(), processName.end());
            
            if (_wcsicmp(entry.szExeFile, wideProcessName.c_str()) == 0) {
                CloseHandle(snapshot);
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return NULL;
}

uintptr_t findSymbolAddress(const HANDLE processHandle, const char* symbolName) {
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(processHandle));
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            HMODULE moduleHandle = GetModuleHandle(moduleEntry.szModule);
            uintptr_t symbolAddress = reinterpret_cast<uintptr_t>(GetProcAddress(moduleHandle, symbolName));

            if (symbolAddress != 0) {
                CloseHandle(snapshot);
                return symbolAddress;
            }

        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

#endif
