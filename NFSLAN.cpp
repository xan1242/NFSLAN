// NFS LAN server launcher for Most Wanted (2005) and Underground 2
// by Xan/Tenjoin

#include <iostream>
//#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <regex>
#include <filesystem>
#include <signal.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
//#include <winsock2.h>
//#include <windns.h>
//#include <wininet.h>
#include "injector/injector.hpp"
#include "injector/assembly.hpp"

//#pragma comment(lib, "Dnsapi.lib")
//#pragma comment(lib, "wininet.lib")

bool (*StartServer)(char* ServerName, int32_t ForceNameNFSMW, void* Callback, void* CallbackParam);
bool (*IsServerRunning)();
void (*StopServer)();

uintptr_t who_func = 0x1000AAD0;
uintptr_t packet_buffer = 0x10058A5C;

//std::vector<uint32_t> LocalUsers;
std::map<uint32_t, uint32_t> RedirIPs;

//constexpr const char* ipcheckdomain = "myip.opendns.com";
//constexpr const char* ipcheckdomain = "http://myexternalip.com/raw";
//uint32_t external_addr = 0;

//bool QueryExternalIP()
//{
//    PDNS_RECORD pDnsRecord;
//
//    DNS_STATUS status = DnsQuery_A(ipcheckdomain, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &pDnsRecord, NULL);
//    if (status == 0)
//        external_addr = _byteswap_ulong(pDnsRecord->Data.A.IpAddress);
//    
//    return status == 0;
//}

//bool QueryExternalIP() {
//
//    HINTERNET net = InternetOpenA("IP retriever",
//        INTERNET_OPEN_TYPE_PRECONFIG,
//        NULL,
//        NULL,
//        0);
//
//    if (!net)
//        return false;
//
//    HINTERNET conn = InternetOpenUrlA(net,
//        ipcheckdomain,
//        NULL,
//        0,
//        INTERNET_FLAG_RELOAD,
//        0);
//
//    if (!conn)
//        return false;
//
//    char buffer[4096];
//    DWORD read;
//    BOOL status;
//
//    status = InternetReadFile(conn, buffer, sizeof(buffer) / sizeof(buffer[0]), &read);
//    if (!status)
//        return false;
//    InternetCloseHandle(net);
//
//    uint8_t p1;
//    uint8_t p2;
//    uint8_t p3;
//    uint8_t p4;
//
//    sscanf(buffer, "%hhu.%hhu.%hhu.%hhu", &p1, &p2, &p3, &p4);
//
//    external_addr = p1 << 24 | p2 << 16 | p3 << 8 | p4;
//
//    return true;
//}

void who_hook(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uint32_t a4)
{
    reinterpret_cast<void(*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uint32_t)>(who_func)(a0, a1, a2, a3, a4);
    uintptr_t dest_addr_info = *(uint32_t*)(a1 + 0x4);
    uint32_t addr = *(uint32_t*)(dest_addr_info + 0x14);

    printf("sending +who to: %u.%u.%u.%u\n", addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF);
    printf("packet: %s\n", (char*)packet_buffer);
}

uintptr_t lobbyAddrFunc = 0x100025E0;
void hkLobbyAddr(uintptr_t a0, uintptr_t a1, uintptr_t a2, uint32_t addr)
{
    uint32_t setaddr = addr;

    if (RedirIPs.find(addr) != RedirIPs.end())
        setaddr = RedirIPs.at(addr);

    return reinterpret_cast<void(*)(uintptr_t, uintptr_t, uintptr_t, uint32_t)>(lobbyAddrFunc)(a0, a1, a2, setaddr);
}

void PatchServer(uintptr_t base)
{
    //std::cout << "NFSLAN: Querying " << ipcheckdomain << " for external IP address...\n";
    //if (QueryExternalIP())
    //    std::cout << "NFSLAN: Got WAN IP: " <<
    //    (external_addr >> 24 & 0xFF) << '.' <<
    //    (external_addr >> 16 & 0xFF) << '.' <<
    //    (external_addr >> 8 & 0xFF) << '.' <<
    //    (external_addr & 0xFF) << '\n';
    //else
    //    std::cout << "NFSLAN: WARNING: failed to catch WAN IP\n";

    struct PatchAddr1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.eax = *(uint32_t*)(regs.esi + 0x14);
            regs.ecx = *(uint32_t*)(regs.esi + 0x7C);
        }
    }; injector::MakeInline<PatchAddr1>(0x1DC8B + base, 0x1DC93 + base);

    struct PatchPort1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.ecx = *(uint8_t*)(regs.esp + 0x1E);
            regs.edi = *(uint16_t*)(regs.esi + 0x18);
        }
    }; injector::MakeInline<PatchPort1>(0x1DCAD + base, 0x1DCBA + base);

    injector::MakeNOP(0x6ABE + base, 7);

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
    }; injector::MakeInline<PatchAddrAndPort2>(0x7294 + base, 0x729A + base);

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
                }
            }
            //if (strcmp(strSKU, "LOCL") == 0)
            //{
            //    uint32_t connIP = *(uint32_t*)(regs.ebx + 0x14);
            //    printf("NFSLAN: addr %u.%u.%u.%u declared local conn!\n", connIP >> 24 & 0xFF, connIP >> 16 & 0xFF, connIP >> 8 & 0xFF, connIP & 0xFF);
            //    LocalUsers.push_back(connIP);
            //}
        }
    }; injector::MakeInline<CatchLocalSKU>(0x1BEDF + base, 0x1BEE5 + base);

    struct TestLocalSKU
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.edi + 0x14);
            
            if (RedirIPs.find(connIP) != RedirIPs.end())
                regs.eax = RedirIPs.at(connIP);
            else
                regs.eax = *(uint32_t*)(regs.esi + 0x2D0);
        }
    }; injector::MakeInline<TestLocalSKU>(0xAB32 + base, 0xAB38 + base);

    struct TestLocalSKU_LA
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.edi + 0x14);

            if (RedirIPs.find(connIP) != RedirIPs.end())
                regs.ecx = RedirIPs.at(connIP);
            else
                regs.ecx = *(uint32_t*)(regs.esi + 0x2D4);
        }
    }; injector::MakeInline<TestLocalSKU_LA>(0xAB03 + base, 0xAB09 + base);


    struct CatchLocalSKU_TERM
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t a1 = *(uint32_t*)(regs.esp + 0x410);
            uint32_t connIP = *(uint32_t*)(a1 + 0x14);

            //LocalUsers.erase(std::remove(LocalUsers.begin(), LocalUsers.end(), connIP), LocalUsers.end());
            RedirIPs.erase(connIP);

            regs.eax = *(uint32_t*)(regs.esi + 0xA38);
        }
    }; injector::MakeInline<CatchLocalSKU_TERM>(0x99EF + base, 0x99F5 + base);

    //who_func = base + 0xAAD0;
    //packet_buffer = base + 0x58A5C;

    uintptr_t lobbyAddrFunc = 0x25E0 + base;
    injector::MakeCALL(0x26514 + base, hkLobbyAddr);
    injector::MakeCALL(0x26535 + base, hkLobbyAddr);

    //injector::MakeCALL(0xB9CF + base, who_hook);

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

    std::cout << "NFSLAN: Patching the server to work on any network...\n";

    PatchServer((uintptr_t)serverdll);

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
