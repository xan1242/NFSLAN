// NFS LAN server launcher for Most Wanted (2005) and Underground 2
// by Xan/Tenjoin

#include <iostream>
#include <filesystem>
#include <signal.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool (*StartServer)(char* ServerName, int32_t unk1, int32_t unk2);
bool (*IsServerRunning)();
void (*StopServer)();

void SigInterruptHandler(int signum)
{
    if (IsServerRunning())
    {
        std::cout << "NFSLAN: Stopping server...\n";
        StopServer();
    }
    else
    {
        std::cout << "NFSLAN: WARNING - server was NOT running during interrupt!\n";
    }
    exit(signum);
}

int main(int argc, char* argv[])
{
    std::cout << "NFS LAN Server Launcher\n";

    if (argc < 2)
    {
        std::cout << "USAGE: NFSLAN servername\n";
        return -1;
    }

    if (!std::filesystem::exists("server.dll"))
    {
        std::cerr << "ERROR: server.dll not found! Please place the server.dll from the game in this executable's path!\n";
        return -1;
    }

    HMODULE serverdll = LoadLibraryA("server");
    if (!serverdll)
    {
        std::cerr << "ERROR: server.dll failed to load!\n";
        return -1;
    }

    StartServer = (bool(*)(char*, int32_t, int32_t))GetProcAddress(serverdll, "StartServer");
    if (!StartServer)
    {
        std::cerr << "ERROR: could not find function StartServer inside server.dll!\n";
        return -1;
    }
    IsServerRunning = (bool(*)())GetProcAddress(serverdll, "IsServerRunning");
    if (!IsServerRunning)
    {
        std::cerr << "ERROR: could not find function IsServerRunning inside server.dll!\n";
        return -1;
    }
    StopServer = (void(*)())GetProcAddress(serverdll, "StopServer");
    if (!IsServerRunning)
    {
        std::cerr << "ERROR: could not find function StopServer inside server.dll!\n";
        return -1;
    }

    signal(SIGINT, SigInterruptHandler);
    signal(SIGTERM, SigInterruptHandler);

    if (!StartServer(argv[1], 0, 0))
    {
        std::cerr << "ERROR: could not launch server! StartServer returned false!\n";
        return -1;
    }

    if (!IsServerRunning())
    {
        std::cerr << "ERROR: could not launch server! StartServer returned true but IsServerRunning returned false!\n";
        return -1;
    }

    std::cout << "NFSLAN: Server started. To stop gracefully, send CTRL+C to the console\n";
    while (IsServerRunning()) { Sleep(1); }
    if (IsServerRunning())
    {
        std::cout << "NFSLAN: Stopping server...\n";
        StopServer();
    }
    else
    {
        std::cout << "NFSLAN: Server not running anymore, exiting...\n";
    }

    return 0;
}
