#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <map>
#include <vector>
#include <string>
#include <chrono>

#define XK 0x55

template<int N>
static void xr(char (&a)[N]) {
    for (int i = 0; i < N - 1; i++) a[i] ^= XK;
    a[N - 1] = 0;
}

#define ntohs(x) ((((x) & 0xFF) << 8) | (((x) & 0xFF00) >> 8))
#define ntohl(x) ((((x) & 0xFF) << 24) | (((x) & 0xFF00) << 8) | (((x) & 0xFF0000) >> 8) | (((x) & 0xFF000000) >> 24))

typedef enum {
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL,
} TCP_TABLE_CLASS;

typedef struct _MIB_TCPROW_OWNER_PID {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} MIB_TCPROW_OWNER_PID;

typedef struct _MIB_TCPTABLE_OWNER_PID {
    DWORD dwNumEntries;
    MIB_TCPROW_OWNER_PID table[1];
} MIB_TCPTABLE_OWNER_PID, *PMIB_TCPTABLE_OWNER_PID;

struct Conn {
    DWORD state;
    DWORD localAddr;
    WORD  localPort;
    DWORD remoteAddr;
    WORD  remotePort;
};

struct Api {
    HANDLE (WINAPI* OpenProcess)(DWORD, BOOL, DWORD);
    BOOL (WINAPI* CloseHandle)(HANDLE);
    HANDLE (WINAPI* CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL (WINAPI* Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    BOOL (WINAPI* Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    int (WINAPI* WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCCH, LPBOOL);
    HMODULE (WINAPI* LoadLibraryW)(LPCWSTR);
    DWORD (WINAPI* GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);

    bool Init();
};

static Api A;
static bool g_ok = false;

bool Api::Init() {
    char kn[] = { 0x3E, 0x30, 0x27, 0x3B, 0x30, 0x39, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(kn);
    HMODULE hK = GetModuleHandleA(kn);
    if (!hK) return false;

    char la[] = { 0x19, 0x3A, 0x34, 0x31, 0x19, 0x3C, 0x37, 0x27, 0x34, 0x27, 0x2C, 0x02, 0 };
    xr(la);
    FARPROC fpLL = GetProcAddress(hK, la);
    if (!fpLL) return false;
    this->LoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))fpLL;

#define LD(mod, ptr, ...) do { \
    char _b[] = __VA_ARGS__; \
    xr(_b); \
    *(FARPROC*)&ptr = GetProcAddress(mod, _b); \
} while(0)

    LD(hK, OpenProcess,          { 0x1A, 0x25, 0x30, 0x3B, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 });
    LD(hK, CloseHandle,          { 0x16, 0x39, 0x3A, 0x26, 0x30, 0x1D, 0x34, 0x3B, 0x31, 0x39, 0x30, 0 });
    LD(hK, CreateToolhelp32Snapshot, { 0x16, 0x27, 0x30, 0x34, 0x21, 0x30, 0x01, 0x3A, 0x3A, 0x39, 0x3D, 0x30, 0x39, 0x25, 0x66, 0x67, 0x06, 0x3B, 0x34, 0x25, 0x26, 0x3D, 0x3A, 0x21, 0 });
    LD(hK, Process32FirstW,      { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x13, 0x3C, 0x27, 0x26, 0x21, 0x02, 0 });
    LD(hK, Process32NextW,       { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x1B, 0x30, 0x2D, 0x21, 0x02, 0 });
    LD(hK, WideCharToMultiByte,  { 0x02, 0x3C, 0x31, 0x30, 0x16, 0x3D, 0x34, 0x27, 0x01, 0x3A, 0x18, 0x20, 0x39, 0x21, 0x3C, 0x17, 0x2C, 0x21, 0x30, 0 });

    char in[] = { 0x3C, 0x25, 0x3D, 0x39, 0x25, 0x34, 0x25, 0x3C, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(in);
    HMODULE hI = GetModuleHandleA(in);
    if (!hI) {
        WCHAR wi[12];
        for (int i = 0; i < 11; i++) wi[i] = in[i];
        wi[11] = 0;
        hI = this->LoadLibraryW(wi);
    }
    if (hI) {
        LD(hI, GetExtendedTcpTable, { 0x12, 0x30, 0x21, 0x10, 0x2D, 0x21, 0x30, 0x3B, 0x31, 0x30, 0x31, 0x01, 0x36, 0x25, 0x01, 0x34, 0x37, 0x39, 0x30, 0 });
    }

    return true;
}

static std::map<DWORD, std::string> BuildProcessMap() {
    std::map<DWORD, std::string> m;
    HANDLE snap = A.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (A.Process32FirstW(snap, &pe)) {
        do {
            char n[260] = {0};
            A.WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, n, sizeof(n), 0, 0);
            m[pe.th32ProcessID] = n;
        } while (A.Process32NextW(snap, &pe));
    }
    A.CloseHandle(snap);
    return m;
}

static char g_slis[10];
static char g_sest[12];
static char g_sclw[11];
static char g_stmw[10];
static char g_ssyn[9];
static char g_sunk[8];

template<int N>
static void copy_xr(char (&dst)[N], const char* src) {
    for (int i = 0; i < N; i++) dst[i] = src[i];
    xr(dst);
}

static void InitStateStr() {
    copy_xr(g_slis, "\x19\x1C\x06\x01\x10\x1B\x1C\x1B\x12\0");
    copy_xr(g_sest, "\x10\x06\x01\x14\x17\x19\x1C\x06\x1D\x10\x11\0");
    copy_xr(g_sclw, "\x16\x19\x1A\x06\x10\x0A\x02\x14\x1C\x01\0");
    copy_xr(g_stmw, "\x01\x1C\x18\x10\x0A\x02\x14\x1C\x01\0");
    copy_xr(g_ssyn, "\x06\x0C\x1B\x0A\x06\x10\x1B\x01\0");
    copy_xr(g_sunk, "\0\x3B\x3E\x3B\x3A\x22\x3B\0");
}

static const char* StateStr(DWORD s) {
    switch (s) {
        case 2:  return g_slis;
        case 5:  return g_sest;
        case 8:  return g_sclw;
        case 11: return g_stmw;
        case 3:  return g_ssyn;
        default: return g_sunk;
    }
}

static void FormatIP(DWORD ip, char* out) {
    sprintf(out, "%d.%d.%d.%d",
        (ip >> 0) & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF);
}

int main() {
    InitStateStr();
    if (!A.Init()) {
        printf("[!] Failed to initialize API\n");
        getchar();
        return 1;
    }

    char caption[] = { 0x19, 0x1A, 0x16, 0x14, 0x19, 0x1D, 0x1A, 0x06, 0x01, 0x75, 0x06, 0x16, 0x14, 0x1B, 0x1B, 0x10, 0x07, 0 };
    xr(caption);
    char subcap[] = { 0x01, 0x16, 0x05, 0x75, 0x30, 0x3B, 0x31, 0x25, 0x3A, 0x3C, 0x3B, 0x21, 0x26, 0x75, 0x37, 0x2C, 0x75, 0x25, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 };
    xr(subcap);
    char scanning[] = { 0x06, 0x36, 0x34, 0x3B, 0x3B, 0x3C, 0x3B, 0x32, 0x75, 0x01, 0x16, 0x05, 0x75, 0x36, 0x3A, 0x3B, 0x3B, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x26, 0x7B, 0x7B, 0x7B, 0 };
    xr(scanning);

    printf("\n[+] %s\n", caption);
    printf("[+] %s\n", subcap);
    printf("\n[+] %s\n", scanning);
    fflush(stdout);

    auto t1 = std::chrono::high_resolution_clock::now();

    std::map<DWORD, std::string> procs = BuildProcessMap();

    std::map<DWORD, std::vector<Conn>> pidConns;

    if (A.GetExtendedTcpTable) {
        ULONG size = 0;
        A.GetExtendedTcpTable(nullptr, &size, FALSE, 2, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0) {
            char* buf = new char[size];
            PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)buf;
            if (A.GetExtendedTcpTable(table, &size, FALSE, 2, TCP_TABLE_OWNER_PID_ALL, 0) == 0) {
                char localhost[] = { 0x64, 0x67, 0x62, 0x7B, 0x65, 0x7B, 0x65, 0x7B, 0x64, 0 };
                xr(localhost);
                DWORD localhostN = 0x0100007F;

                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    auto& r = table->table[i];
                    DWORD la = r.dwLocalAddr;
                    DWORD ra = r.dwRemoteAddr;
                    bool isLocal = (la == localhostN) || (ra == localhostN);

                    if (isLocal) {
                        Conn c;
                        c.state = r.dwState;
                        c.localAddr = la;
                        c.localPort = ntohs((WORD)r.dwLocalPort);
                        c.remoteAddr = ra;
                        c.remotePort = ntohs((WORD)r.dwRemotePort);
                        pidConns[r.dwOwningPid].push_back(c);
                    }
                }
            }
            delete[] buf;
        }
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    char header[] = { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x30, 0x26, 0x75, 0x22, 0x3C, 0x21, 0x3D, 0x75, 0x39, 0x3A, 0x36, 0x34, 0x39, 0x3D, 0x3A, 0x26, 0x21, 0x75, 0x36, 0x3A, 0x3B, 0x3B, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x26, 0x6F, 0 };
    xr(header);
    char snone[] = { 0x1B, 0x3A, 0x75, 0x39, 0x3A, 0x36, 0x34, 0x39, 0x3D, 0x3A, 0x26, 0x21, 0x75, 0x36, 0x3A, 0x3B, 0x3B, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x26, 0x75, 0x33, 0x3A, 0x20, 0x3B, 0x31, 0x7B, 0 };
    xr(snone);
    char spid[] = { 0x05, 0x1C, 0x11, 0 };
    xr(spid);
    char sproc[] = { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 };
    xr(sproc);
    char sconn[] = { 0x16, 0x3A, 0x3B, 0x3B, 0x30, 0x36, 0x21, 0x3C, 0x3A, 0x3B, 0x26, 0 };
    xr(sconn);
    char slh[] = { 0x0E, 0x39, 0x3A, 0x36, 0x34, 0x39, 0x3D, 0x3A, 0x26, 0x21, 0x08, 0 };
    xr(slh);

    printf("\n[+] %s\n", header);
    printf("\n");

    if (pidConns.empty()) {
        printf("[+] %s\n", snone);
    } else {
        char ipbuf[32];
        for (auto& kv : pidConns) {
            DWORD pid = kv.first;
            auto& conns = kv.second;

            auto it = procs.find(pid);
            const char* pname = it != procs.end() ? it->second.c_str() : "?";

            printf("[+] %s %-6u  %s  (%zu %s)\n", spid, pid, pname, conns.size(), sconn);

            for (auto& c : conns) {
                FormatIP(c.localAddr, ipbuf);
                printf("[+]     %s  %s:%d", StateStr(c.state), ipbuf, c.localPort);

                if (c.state != 2) {
                    FormatIP(c.remoteAddr, ipbuf);
                    printf(" -> %s:%d", ipbuf, c.remotePort);
                } else {
                    printf("  %s", slh);
                }
                printf("\n");
            }
            printf("\n");
        }
    }

    char sdone[] = { 0x06, 0x36, 0x34, 0x3B, 0x3B, 0x30, 0x31, 0x75, 0x3C, 0x3B, 0 };
    xr(sdone);
    char sms[] = { 0x38, 0x26, 0 };
    xr(sms);
    char sexit[] = { 0x05, 0x27, 0x30, 0x26, 0x26, 0x75, 0x34, 0x3B, 0x2C, 0x75, 0x3E, 0x30, 0x2C, 0x75, 0x21, 0x3A, 0x75, 0x30, 0x2D, 0x3C, 0x21, 0x7B, 0 };
    xr(sexit);

    printf("[+] %s %lld %s\n\n", sdone, (long long)ms, sms);
    printf("[+] %s\n", sexit);
    getchar();

    return 0;
}
