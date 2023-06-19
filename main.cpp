#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>

DWORD_PTR GetProcessId(const char* processName);

int main(const int argc, const char* argv[]) {
    if (argc > 2) {
        const char* dllPath = argv[2];
        DWORD_PTR processId = GetProcessId(argv[1]);
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);

        if (handle && handle != INVALID_HANDLE_VALUE) {
            if (!std::filesystem::exists(dllPath)) {
                std::cout << "Dll File is not found." << std::endl;
                return EXIT_FAILURE;
            }

            std::cout << "Injecting to " << argv[1] << "..." << std::endl;

            void* allocateLoc = VirtualAllocEx(handle, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            WriteProcessMemory(handle, allocateLoc, dllPath, strlen(dllPath), nullptr);
            HANDLE thread = CreateRemoteThread(handle, nullptr, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, allocateLoc, 0, nullptr);

            if (thread) {
                CloseHandle(thread);
            }

            return EXIT_SUCCESS;
        }

        std::cout << "Process Not Found." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "SimpleInjector (ProcessName) (DllFilePath)" << std::endl;
    return EXIT_SUCCESS;
}

DWORD_PTR GetProcessId(const char* processName) {
    DWORD processId = 0;
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE32, 0);

    if (handle != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);

        if (Process32First(handle, &entry)) {
            while (Process32Next(handle, &entry)) {
                if (!_stricmp(entry.szExeFile, processName)) {
                    processId = entry.th32ProcessID;
                    break;
                }
            }
        }
    }

    CloseHandle(handle);
    return processId;
}
