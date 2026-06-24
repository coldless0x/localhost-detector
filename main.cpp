#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <map>
#include <vector>
#include <string>

#pragma comment(linker, "/SUBSYSTEM:console")

#define XK 0x55

template<int N>
static void xr(char (&a)[N]) {
    for (int i = 0; i < N - 1; i++) a[i] ^= XK;
    a[N - 1] = 0;
}

#define ntohs(x) ((((x) & 0xFF) << 8) | (((x) & 0xFF00) >> 8))
#define ntohl(x) ((((x) & 0xFF) << 24) | (((x) & 0xFF00) << 8) | (((x) & 0xFF0000) >> 8) | (((x) & 0xFF000000) >> 24))

typedef enum {
    TCP_TABLE_OWNER_PID_ALL = 5,
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

typedef struct _MIB_UDPROW_OWNER_PID {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
} MIB_UDPROW_OWNER_PID;

typedef struct _MIB_UDPTABLE_OWNER_PID {
    DWORD dwNumEntries;
    MIB_UDPROW_OWNER_PID table[1];
} MIB_UDPTABLE_OWNER_PID, *PMIB_UDPTABLE_OWNER_PID;

struct Conn {
    bool  isUdp;
    bool  bindAll;
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
    DWORD (WINAPI* GetExtendedUdpTable)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);

    bool Init() {
        char kn[] = { 0x3E, 0x30, 0x27, 0x3B, 0x30, 0x39, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0 };
        xr(kn);
        HMODULE hK = GetModuleHandleA(kn);
        if (!hK) return false;

        char la[] = { 0x19, 0x3A, 0x34, 0x31, 0x19, 0x3C, 0x37, 0x27, 0x34, 0x27, 0x2C, 0x02, 0 };
        xr(la);
        FARPROC fpLL = GetProcAddress(hK, la);
        if (!fpLL) return false;
        this->LoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))fpLL;

        char _op[] = { 0x1A, 0x25, 0x30, 0x3B, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 }; xr(_op); *(FARPROC*)&OpenProcess = GetProcAddress(hK, _op);
        char _ch[] = { 0x16, 0x39, 0x3A, 0x26, 0x30, 0x1D, 0x34, 0x3B, 0x31, 0x39, 0x30, 0 }; xr(_ch); *(FARPROC*)&CloseHandle = GetProcAddress(hK, _ch);
        char _ct[] = { 0x16, 0x27, 0x30, 0x34, 0x21, 0x30, 0x01, 0x3A, 0x3A, 0x39, 0x3D, 0x30, 0x39, 0x25, 0x66, 0x67, 0x06, 0x3B, 0x34, 0x25, 0x26, 0x3D, 0x3A, 0x21, 0 }; xr(_ct); *(FARPROC*)&CreateToolhelp32Snapshot = GetProcAddress(hK, _ct);
        char _pf[] = { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x13, 0x3C, 0x27, 0x26, 0x21, 0x02, 0 }; xr(_pf); *(FARPROC*)&Process32FirstW = GetProcAddress(hK, _pf);
        char _pn[] = { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x1B, 0x30, 0x2D, 0x21, 0x02, 0 }; xr(_pn); *(FARPROC*)&Process32NextW = GetProcAddress(hK, _pn);
        char _wc[] = { 0x02, 0x3C, 0x31, 0x30, 0x16, 0x3D, 0x34, 0x27, 0x01, 0x3A, 0x18, 0x20, 0x39, 0x21, 0x3C, 0x17, 0x2C, 0x21, 0x30, 0 }; xr(_wc); *(FARPROC*)&WideCharToMultiByte = GetProcAddress(hK, _wc);

        char in[] = { 0x3C, 0x25, 0x3D, 0x39, 0x25, 0x34, 0x25, 0x3C, 0x7B, 0x31, 0x39, 0x39, 0 };
        xr(in);
        HMODULE hI = GetModuleHandleA(in);
        if (!hI) {
            WCHAR wi[64] = {};
            for (int i = 0; in[i] && i < 63; i++) wi[i] = (WCHAR)in[i];
            hI = this->LoadLibraryW(wi);
        }
        if (hI) {
            char _tc[] = { 0x12, 0x30, 0x21, 0x10, 0x2D, 0x21, 0x30, 0x3B, 0x31, 0x30, 0x31, 0x01, 0x36, 0x25, 0x01, 0x34, 0x37, 0x39, 0x30, 0 }; xr(_tc); *(FARPROC*)&GetExtendedTcpTable = GetProcAddress(hI, _tc);
            char _ud[] = { 0x12, 0x30, 0x21, 0x10, 0x2D, 0x21, 0x30, 0x3B, 0x31, 0x30, 0x31, 0x00, 0x31, 0x25, 0x01, 0x34, 0x37, 0x39, 0x30, 0 }; xr(_ud); *(FARPROC*)&GetExtendedUdpTable = GetProcAddress(hI, _ud);
        }

        return GetExtendedTcpTable != nullptr;
    }
};

static Api A;

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

template<int N>
static void copy_xr(char (&dst)[N], const char* src) {
    for (int i = 0; i < N; i++) dst[i] = src[i];
    xr(dst);
}

static const char* StateStr(DWORD s) {
    static char g_slis[10]; static char g_sest[12]; static char g_sclw[11];
    static char g_stmw[10]; static char g_ssyn[9];  static char g_sunk[8];
    static bool init = false;
    if (!init) {
        copy_xr(g_slis, "\x39\x3C\x26\x21\x30\x3B\x3C\x3B\x32\0");
        copy_xr(g_sest, "\x30\x26\x21\x34\x37\x39\x3C\x26\x3D\x30\x31\0");
        copy_xr(g_sclw, "\x36\x39\x3A\x26\x30\x0A\x22\x34\x3C\x21\0");
        copy_xr(g_stmw, "\x21\x3C\x38\x30\x0A\x22\x34\x3C\x21\0");
        copy_xr(g_ssyn, "\x26\x2C\x3B\x0A\x26\x30\x3B\x21\0");
        copy_xr(g_sunk, "\x20\x3B\x3E\x3B\x3A\x22\x3B\0");
        init = true;
    }
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
    sprintf(out, "%d.%d.%d.%d", (ip >> 0) & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

static bool IsLoopbackV4(DWORD ip) { return (ip & 0xFF) == 0x7F; }
static bool IsAnyV4(DWORD ip) { return ip == 0; }
static bool IsTransientTcp(DWORD state) {
    switch (state) {
        case 6: case 7: case 8: case 9: case 10: case 11: case 12: return true;
        default: return false;
    }
}
static bool IsSystemPort(WORD port) {
    switch (port) {
        case 135: case 445: case 5040: case 5357: case 7680: return true;
        default: return port >= 49664 && port <= 49680;
    }
}

static bool IsRelevantTcp(DWORD la, DWORD ra, WORD localPort, DWORD state, bool* bindAll) {
    *bindAll = false;
    if (IsTransientTcp(state)) return false;
    if (IsLoopbackV4(la) || IsLoopbackV4(ra)) return true;
    if (state == 2 && IsAnyV4(la) && localPort >= 1024 && !IsSystemPort(localPort)) {
        *bindAll = true;
        return true;
    }
    return false;
}

static bool IsRelevantUdp(DWORD la, WORD localPort, bool* bindAll) {
    *bindAll = false;
    if (IsLoopbackV4(la)) return true;
    if (IsAnyV4(la) && localPort >= 1024 && !IsSystemPort(localPort)) {
        *bindAll = true;
        return true;
    }
    return false;
}

template<typename Fn>
static char* QueryNetTable(Fn query, ULONG af) {
    ULONG size = 0;
    query(nullptr, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return nullptr;

    for (int attempt = 0; attempt < 3; attempt++) {
        char* buf = new char[size];
        ULONG got = size;
        if (query(buf, &got, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            return buf;
        delete[] buf;
        if (got <= size) break;
        size = got;
    }
    return nullptr;
}

int main() {
    char sTitle[] = {0x19,0x3A,0x36,0x34,0x39,0x3D,0x3A,0x26,0x21,0x75,0x16,0x3A,0x3B,0x3B,0x30,0x36,0x21,0x3C,0x3A,0x3B,0x75,0x06,0x36,0x34,0x3B,0x3B,0x30,0x27,0}; xr(sTitle);
    char sStats[] = {0x75,0x75,0x01,0x16,0x05,0x6F,0x75,0x70,0x20,0x75,0x75,0x29,0x75,0x75,0x00,0x11,0x05,0x6F,0x75,0x70,0x20,0}; xr(sStats);
    char sHeader[] = {0x75,0x75,0x05,0x1C,0x11,0x75,0x75,0x75,0x05,0x07,0x1A,0x16,0x10,0x06,0x06,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x14,0x11,0x11,0x07,0x10,0x06,0x06,0x6F,0x05,0x1A,0x07,0x01,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x75,0x06,0x01,0x14,0x01,0x10,0}; xr(sHeader);
    char sLine[] = {0x75,0x70,0x60,0x20,0x75,0x75,0x70,0x78,0x67,0x65,0x26,0x75,0x75,0x70,0x78,0x67,0x64,0x26,0x75,0x75,0x70,0x26,0x5F,0}; xr(sLine);
    char sEmpty[] = {0x75,0x75,0x3B,0x3A,0x75,0x39,0x3A,0x36,0x34,0x39,0x3D,0x3A,0x26,0x21,0x75,0x36,0x3A,0x3B,0x3B,0x30,0x36,0x21,0x3C,0x3A,0x3B,0x26,0x75,0x33,0x3A,0x20,0x3B,0x31,0}; xr(sEmpty);
    char sFound[] = {0x75,0x75,0x70,0x20,0x75,0x39,0x3A,0x36,0x34,0x39,0x3D,0x3A,0x26,0x21,0x75,0x36,0x3A,0x3B,0x3B,0x30,0x36,0x21,0x3C,0x3A,0x3B,0x26,0x75,0x33,0x3A,0x20,0x3B,0x31,0x5F,0}; xr(sFound);
    char sDone[] = {0x75,0x75,0x31,0x3A,0x3B,0x30,0x7B,0}; xr(sDone);
    char sUdp[] = {0x00,0x11,0x05,0}; xr(sUdp);
    char sBindAll[] = {0x37,0x3C,0x3B,0x31,0x78,0x34,0x39,0x39,0}; xr(sBindAll);

    if (!A.Init()) {
        printf("  error: api init failed\n");
        return 1;
    }

    auto procs = BuildProcessMap();
    std::map<DWORD, std::vector<Conn>> pidConns;
    DWORD tcpCount = 0, udpCount = 0;

    if (A.GetExtendedTcpTable) {
        if (char* buf = QueryNetTable(A.GetExtendedTcpTable, 2)) {
            PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& r = table->table[i];
                WORD port = ntohs((WORD)r.dwLocalPort);
                bool bindAll = false;
                if (!IsRelevantTcp(r.dwLocalAddr, r.dwRemoteAddr, port, r.dwState, &bindAll))
                    continue;

                WORD remPort = (WORD)ntohs(r.dwRemotePort);
                Conn c = { false, bindAll, r.dwState, r.dwLocalAddr, port, r.dwRemoteAddr, remPort };
                if (r.dwOwningPid != 0) pidConns[r.dwOwningPid].push_back(c);
                tcpCount++;
            }
            delete[] buf;
        }
    }

    if (A.GetExtendedUdpTable) {
        if (char* buf = QueryNetTable(A.GetExtendedUdpTable, 2)) {
            PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID)buf;
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& r = table->table[i];
                WORD port = ntohs((WORD)r.dwLocalPort);
                bool bindAll = false;
                if (!IsRelevantUdp(r.dwLocalAddr, port, &bindAll))
                    continue;

                Conn c = { true, bindAll, 0, r.dwLocalAddr, port, 0, 0 };
                if (r.dwOwningPid != 0) pidConns[r.dwOwningPid].push_back(c);
                udpCount++;
            }
            delete[] buf;
        }
    }

    printf("%s\n", sTitle);

    if (pidConns.empty()) {
        printf("%s\n", sEmpty);
    } else {
        printf(sStats, tcpCount, udpCount);
        printf("\n");
        printf("%s\n", sHeader);

        char la[32];
        DWORD total = 0;
        for (auto& kv : pidConns) {
            DWORD pid = kv.first;
            auto it = procs.find(pid);
            const char* pname = it != procs.end() ? it->second.c_str() : "?";

            for (auto& c : kv.second) {
                FormatIP(c.localAddr, la);

                const char* stateStr;
                if (c.isUdp) {
                    stateStr = sUdp;
                } else if (c.bindAll) {
                    stateStr = sBindAll;
                } else {
                    stateStr = StateStr(c.state);
                }

                char addrPort[22];
                snprintf(addrPort, sizeof(addrPort), "%s:%u", la, c.localPort);

                printf(sLine, pid, pname, addrPort, stateStr);
                total++;
            }
        }

        printf("\n");
        printf(sFound, total);
    }

    printf("%s\n", sDone);
    getchar();
    return 0;
}
