// NFS LAN server launcher for Most Wanted (2005) and Underground 2
// by Xan/Tenjoin

#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <regex>
#include <filesystem>
#include <signal.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include "injector/injector.hpp"
#include "injector/assembly.hpp"
#include "injector/hooking/Hooking.Patterns.h"
#include "Network.h"
#include <thread>

bool (*StartServer)(char* ServerName, int32_t ForceNameNFSMW, void* Callback, void* CallbackParam);
bool (*IsServerRunning)();
void (*StopServer)();

bool bDisablePatching = false;

uintptr_t who_func = 0x1000AAD0;
uintptr_t packet_buffer = 0x10058A5C;

std::map<uint32_t, uint32_t> RedirIPs;
std::vector<uint32_t> LocalUsers;

uint32_t lobbyClientDestAddr = 0;

// requires that the client is using the LanIP plugin!
void LocalChallengeClient(uint32_t addr)
{
    constexpr DWORD ChallengeTimeOut = 1000; // 1sec timeout
    uint32_t query = 0x6A093EC9; // strhash of "LOCAL?" 6A093EC9
    uint32_t response = 0;
    char strIP[32];
    sprintf(strIP, "%u.%u.%u.%u", addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF);

    std::cout << "NFSLAN: challenging addr " << strIP << '\n';

    try
    {
        UDPSocket Socket;
        Socket.SetTimeout(ChallengeTimeOut);
        Socket.SendTo(strIP, 9901, (char*)&query, sizeof(uint32_t));
        Socket.RecvFrom((char*)&response, sizeof(uint32_t));
        if (response == 0x8DB682D1) // strhash of "YESIMLOCAL" 8DB682D1
        {
            sprintf(strIP, "%u.%u.%u.%u", addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF);
            std::cout << "NFSLAN: addr " << strIP << " is local!\n";
            LocalUsers.push_back(addr);
        }
        Socket.~UDPSocket();
    }
    catch (std::exception& ex)
    {
        std::cout << "NFSLAN: " << ex.what() << '\n';
        return;
    }
}

uintptr_t lobbyAddrFunc = 0x100025E0;
void hkLobbyAddr(uintptr_t a0, uintptr_t a1, uintptr_t a2, uint32_t addr)
{
    uint32_t setaddr = addr;

    if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), lobbyClientDestAddr) != LocalUsers.cend())
    {
        if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), addr) != LocalUsers.cend())
        {
            setaddr = addr;
        }
    }
    else if (RedirIPs.find(addr) != RedirIPs.end())
        setaddr = RedirIPs.at(addr);

    //printf("Addr: %X Dest: %X\n", setaddr, lobbyClientDestAddr);

    return reinterpret_cast<void(*)(uintptr_t, uintptr_t, uintptr_t, uint32_t)>(lobbyAddrFunc)(a0, a1, a2, setaddr);
}

// server patches for MW server (server.dll in MW and Carbon (yes really, Carbon's is slightly different but it's there))
void PatchServerMW(uintptr_t base)
{
    // base is usually 10000000 but it's better safe than sorry
    hook::details::set_process_base(base);

    // 1001DC8B - 1001DC93
    uintptr_t loc_1001DC8B = reinterpret_cast<uintptr_t>(hook::pattern("83 C4 08 50 E8 ? ? ? ? 8B 4E 7C 83 C4 08 6A 00 8B D8 68").get_first(0)) + 4;

    // 1001DCAD - 1001DCBA
    uintptr_t loc_1001DCAD = loc_1001DC8B + 0x22;

    // 10006ABE
    uintptr_t loc_10006ABE = reinterpret_cast<uintptr_t>(hook::pattern("C7 46 14 FE FF FF FF C6 01 00").get_first(0));

    // 10007294
    uintptr_t loc_10007294 = reinterpret_cast<uintptr_t>(hook::pattern("8B 4E 5C 8B 56 60 8B E8 8B 45 18 50").get_first(0));

    // 1001BEDF
    uintptr_t loc_1001BEDF = reinterpret_cast<uintptr_t>(hook::pattern("8B 82 38 0A 00 00 8D 88 70 03 00 00 51 8B 8A 6C 0D 00 00").get_first(0));

    // 1000AB32
    uintptr_t loc_1000AB32 = reinterpret_cast<uintptr_t>(hook::pattern("8B 86 D0 02 00 00 8D 8E D0 00 00 00 51 8B").get_first(0));

    // 1000AB03
    uintptr_t loc_1000AB03 = reinterpret_cast<uintptr_t>(hook::pattern("8B 8E D4 02 00 00 52 8B 96 18 03 00 00").get_first(0));

    // 100099EF
    uintptr_t loc_100099EF = reinterpret_cast<uintptr_t>(hook::pattern("8B 86 38 0A 00 00 85 C0 BB ? ? ? ? 74 13 50 E8").get_first(0));

    // 10026514
    uintptr_t loc_10026514 = reinterpret_cast<uintptr_t>(hook::pattern("55 8D 4C 24 14 51 57 53 E8 ? ? ? ? 56 8D 54 24 24 68 ? ? ? ? 52 E8 ? ? ? ? 8B 44 24 50").get_first(0)) + 8;

    // 1001363D
    uintptr_t loc_1001363D = reinterpret_cast<uintptr_t>(hook::pattern("C7 45 5C F4 FF 00 00 89 75 50 89 75 54 89 75 58").get_first(0)) + 7;

    // 10013C95
    uintptr_t loc_10013C95 = reinterpret_cast<uintptr_t>(hook::pattern("51 89 7D 50 89 7D 54 89 7D 58 8B 4B 10").get_first(0)) + 1;


    struct PatchAddr1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.eax = *(uint32_t*)(regs.esi + 0x14);
            regs.ecx = *(uint32_t*)(regs.esi + 0x7C);
        }
    }; injector::MakeInline<PatchAddr1>(loc_1001DC8B, loc_1001DC8B + 8);

    struct PatchPort1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.ecx = *(uint8_t*)(regs.esp + 0x1E);
            regs.edi = *(uint16_t*)(regs.esi + 0x18);
        }
    }; injector::MakeInline<PatchPort1>(loc_1001DCAD, loc_1001DCAD + 0xD);

    // disable IP address invalidation at this point
    injector::MakeNOP(loc_10006ABE, 7);

    struct PatchAddrAndPort2
    {
        void operator()(injector::reg_pack& regs)
        {
            *(uint32_t*)(regs.eax + 0x18) = *(uint32_t*)(regs.esi + 0x14);
            //*(uint16_t*)(regs.eax + 0xC) = *(uint16_t*)(regs.esi + 0x18);
            *(int32_t*)(regs.esi + 0x14) = -5;
            regs.ecx = *(uint32_t*)(regs.esi + 0x5C);
            regs.edx = *(uint32_t*)(regs.esi + 0x60);
        }
    }; injector::MakeInline<PatchAddrAndPort2>(loc_10007294, loc_10007294 + 6);

    struct CatchLocalSKU
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.eax = *(uint32_t*)(regs.edx + 0xA38);
            char* strSKU = (char*)(regs.eax + 0x80);
            if (std::regex_match(strSKU, std::regex("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$")))
            {
                uint32_t connIP = *(uint32_t*)(regs.ebx + 0x14);
                uint32_t incomingIP = 0;
                uint8_t p1, p2, p3, p4;
                sscanf(strSKU, "%hhu.%hhu.%hhu.%hhu", &p1, &p2, &p3, &p4);
                incomingIP = p1 << 24 | p2 << 16 | p3 << 8 | p4;

                if (incomingIP != connIP)
                {
                    RedirIPs.insert(std::pair(connIP, incomingIP));

                    // challenge the connIP to see if it's local to the server, and if it is, add it to its own list
                    std::thread(LocalChallengeClient, connIP).detach();
                }
            }
        }
    }; injector::MakeInline<CatchLocalSKU>(loc_1001BEDF, loc_1001BEDF + 6);

    struct TestLocalSKU
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.esi + 0x2D0);
            uint32_t destIP = *(uint32_t*)(regs.edi + 0x14);

            if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), destIP) != LocalUsers.cend())
            {
                if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), connIP) != LocalUsers.cend())
                {
                    regs.eax = *(uint32_t*)(regs.esi + 0x2D0);
                }
            }
            else if (RedirIPs.find(connIP) != RedirIPs.end())
            {
                regs.eax = RedirIPs.at(connIP);
            }
            else
                regs.eax = *(uint32_t*)(regs.esi + 0x2D0);
        }
    }; injector::MakeInline<TestLocalSKU>(loc_1000AB32, loc_1000AB32 + 6);

    struct TestLocalSKU_LA
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.esi + 0x2D4);
            uint32_t destIP = *(uint32_t*)(regs.edi + 0x14);

            if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), destIP) != LocalUsers.cend())
            {
                if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), connIP) != LocalUsers.cend())
                {
                    regs.ecx = *(uint32_t*)(regs.esi + 0x2D4);
                }
            }
            else if (RedirIPs.find(connIP) != RedirIPs.end())
            {
                regs.ecx = RedirIPs.at(connIP);
            }
            else
                regs.ecx = *(uint32_t*)(regs.esi + 0x2D4);
        }
    }; injector::MakeInline<TestLocalSKU_LA>(loc_1000AB03, loc_1000AB03 + 6);


    struct CatchLocalSKU_TERM
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t a1 = *(uint32_t*)(regs.esp + 0x410);
            uint32_t connIP = *(uint32_t*)(a1 + 0x14);

            LocalUsers.erase(std::remove(LocalUsers.begin(), LocalUsers.end(), connIP), LocalUsers.end());
            RedirIPs.erase(connIP);

            regs.eax = *(uint32_t*)(regs.esi + 0xA38);
        }
    }; injector::MakeInline<CatchLocalSKU_TERM>(loc_100099EF, loc_100099EF + 6);

    struct CatchDestAddr1
    {
        void operator()(injector::reg_pack& regs)
        {
            lobbyClientDestAddr = *(uint32_t*)(regs.ebp + 0x14);
            *(uint32_t*)(regs.ebp + 0x50) = 0;
            *(uint32_t*)(regs.ebp + 0x54) = 0;
        }
    }; injector::MakeInline<CatchDestAddr1>(loc_1001363D, loc_1001363D + 6);

    struct CatchDestAddr2
    {
        void operator()(injector::reg_pack& regs)
        {
            lobbyClientDestAddr = *(uint32_t*)(regs.ebp + 0x14);
            *(uint32_t*)(regs.ebp + 0x50) = 0;
            *(uint32_t*)(regs.ebp + 0x54) = 0;
        }
    }; injector::MakeInline<CatchDestAddr2>(loc_10013C95, loc_10013C95 + 6);

    lobbyAddrFunc = reinterpret_cast<uintptr_t>(injector::MakeCALL(loc_10026514, hkLobbyAddr).get_raw<void>());
    injector::MakeCALL(loc_10026514 + 0x21, hkLobbyAddr);
}

void PatchServerUG2(uintptr_t base)
{
    std::cout << "NFSLAN: Server patching for NFS Underground 2 not yet implemented.\n";
}

bool bIsUnderground2Server(uintptr_t base)
{
    // base is usually 10000000 but it's better safe than sorry
    hook::details::set_process_base(base);

    // 100013FB in MW, 100013EC in UG2
    uintptr_t defServerNamePtr = reinterpret_cast<uintptr_t>(hook::pattern("6A 03 68 66 76 64 61 53").get_first(0)) + 0x12;
    char* defServerName = *(char**)defServerNamePtr;
    if ((strstr(defServerName, "Underground 2") == nullptr) && (defServerName != nullptr))
        return false;
    return true;
}

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
        std::cout << "USAGE: NFSLAN servername [-n]\n" << "-n = no server patching\n";
        return -1;
    }

    if (argc >= 3)
    {
        if (argv[2][0] == '-' && argv[2][1] == 'n')
        {
            bDisablePatching = true;
        }
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

    StartServer = (bool(*)(char*, int32_t, void*, void*))GetProcAddress(serverdll, "StartServer");
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
    if (!StopServer)
    {
        std::cerr << "ERROR: could not find function StopServer inside server.dll!\n";
        return -1;
    }

    if (!bDisablePatching)
    {
        std::cout << "NFSLAN: Patching the server to work on any network...\n";

        if (bIsUnderground2Server((uintptr_t)serverdll))
            PatchServerUG2((uintptr_t)serverdll);
        else
            PatchServerMW((uintptr_t)serverdll);
    }

    signal(SIGINT, SigInterruptHandler);
    signal(SIGTERM, SigInterruptHandler);

    if (!StartServer(argv[1], 0, nullptr, nullptr))
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
