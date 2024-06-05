// d4en6.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <future>
#include <chrono> 
#include <atomic> 
#include <sstream>
#include <wincrypt.h>


struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    std::string path;
    SIZE_T memoryUsage;
};


std::vector<ProcessInfo> getProcessList() {
    std::vector<ProcessInfo> processes;

    // Создаем снимок всех процессов
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot: " << GetLastError() << std::endl;
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Error getting first process: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return processes;
    }

    do {
        ProcessInfo info;
        info.pid = pe32.th32ProcessID;
        info.name = pe32.szExeFile;

        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
        if (hProcess != NULL) {
            
            char filePath[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, NULL, filePath, MAX_PATH) != 0) {
                info.path = filePath;
            }
            
            PROCESS_MEMORY_COUNTERS_EX pmc;
            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                info.memoryUsage = pmc.PrivateUsage;
            }

            CloseHandle(hProcess);
        }

        processes.push_back(info);
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    return processes;
}

int main() {
    
    std::vector<ProcessInfo> processes = getProcessList();

    
    for (const auto& process : processes) {
        
        std::wcout << L"PID: " << process.pid << L", Name: " << process.name << L", ";
        std::cout << "Path: " << process.path;
        std::wcout << L", Memory Usage: " << process.memoryUsage << L" bytes" << std::endl;

    }

    return 0;
}
