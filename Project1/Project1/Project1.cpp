#include "pch.h"
#include <iostream>
#include "adddrex.h"

int main(int argc, char* argv[]) {
    std::cout << "Hello World!" << std::endl;

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <process name> <dll file>" << std::endl;
        return 1;
    }

    std::string processName = argv[1];
    const char* dllPath = argv[2];

    HANDLE processHandle = GetProcessHandleFromName(processName);

    if (processHandle == nullptr) {
        std::cerr << "Processus non trouvé." << std::endl;
        return 1;
    }

    std::cout << "Process Handle Found : " << processHandle << std::endl;

    inject(processHandle, dllPath);
    CloseHandle(processHandle);

    return 0;
}
