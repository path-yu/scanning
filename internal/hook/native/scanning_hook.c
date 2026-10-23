// Scanning 进程注入 Hook DLL（Windows x64）
//
// 原理：参考 Proxifier 的用户态方案，不依赖 WinDivert / 内核驱动。
// 由 Go 注入器通过 CreateRemoteThread + LoadLibrary 加载到目标进程后：
//   1. 扫描目标进程所有模块的导入地址表（IAT），把 ws2_32!connect /
//      ws2_32!WSAConnect 的导入项替换为本 DLL 的 detour；
//   2. 当目标进程发起 TCP 连接（仅配置的端口，默认 80/443）时，先把连接
//      改接到本机 Scanning 代理，并在 detour 内完成 HTTP CONNECT 握手；
//   3. 代理看到的是原始目标 IP:端口，可通过 TLS SNI / HTTP Host 还原域名，
//      复用现有 MITM、规则、断点、重放与 Flow 分析能力。
//
// 说明：
//   - 使用 IAT 替换而非 inline hook，避免指令长度解码，稳定性更高；
//   - 后台线程定期重扫模块，覆盖延迟加载与运行期新加载的 DLL；
//   - 通过进程内日志文件记录重定向结果，便于排查注入是否生效。

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#ifndef WSAAPI
#define WSAAPI __stdcall
#endif

#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x00000001
#endif

typedef struct _SCANNING_CFG_CALL_TARGET_INFO {
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} SCANNING_CFG_CALL_TARGET_INFO;

typedef BOOL(WINAPI *PFN_SetProcessValidCallTargets)(
    HANDLE Process,
    PVOID VirtualAddress,
    SIZE_T RegionSize,
    ULONG NumberOfOffsets,
    SCANNING_CFG_CALL_TARGET_INFO *OffsetInformation);

typedef int(WSAAPI *FN_CONNECT)(SOCKET, const struct sockaddr *, int);
typedef int(WSAAPI *FN_WSA_CONNECT)(SOCKET, const struct sockaddr *, int,
                                    LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int(WSAAPI *FN_WSA_IOCTL)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD,
                                  LPDWORD, LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL(WSAAPI *FN_CONNECT_EX)(SOCKET, const struct sockaddr *, int, PVOID,
                                    DWORD, LPDWORD, LPOVERLAPPED);

// WSAID_CONNECTEX：{25a207b9-ddf3-4660-8ee9-76e58c74063e}
static const GUID kConnectExGuid = {
    0x25a207b9, 0xddf3, 0x4660, {0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}};

#define HOOK_MAX_PORTS 16
#define HOOK_LOG_LIMIT 5000
#define HOOK_CONNECT_TIMEOUT_MS 10000
#define HOOK_HEADER_LIMIT 4096

static HMODULE g_self = NULL;
static FN_CONNECT g_real_connect = NULL;
static FN_WSA_CONNECT g_real_wsaconnect = NULL;
static FN_WSA_IOCTL g_real_wsaioc = NULL;
static FN_CONNECT_EX g_real_connectex = NULL;
static CRITICAL_SECTION g_lock;
static BOOL g_lock_ready = FALSE;
static BOOL g_enabled = FALSE;
static int g_ports[HOOK_MAX_PORTS];
static int g_port_count = 0;
static struct in_addr g_proxy_v4;
static struct in6_addr g_proxy_v6;
static USHORT g_proxy_port = 0;
static BOOL g_proxy_is_v6 = FALSE;
static WCHAR g_log_path[MAX_PATH];
static LONG g_log_lines = 0;
static DWORD g_pid = 0;
static HANDLE g_ready_event = NULL;
static LONG g_redirect_count = 0;
static LONG g_connect_calls = 0;

static void HookLog(const char *fmt, ...);
static void BuildLogPath(void);
static void EnsureLogDir(void);
static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen);
static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name,
                                  int namelen, LPWSABUF callerData,
                                  LPWSABUF calleeData, LPQOS sqos, LPQOS gqos);
static int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen,
                                LPVOID outBuf, DWORD outLen, LPDWORD bytes,
                                LPWSAOVERLAPPED ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
static BOOL WSAAPI Hook_ConnectEx(SOCKET s, const struct sockaddr *name,
                                  int namelen, PVOID sendBuf, DWORD sendLen,
                                  LPDWORD bytesSent, LPOVERLAPPED ov);

// ---------------------------------------------------------------------------
// 配置与日志
// ---------------------------------------------------------------------------

static void GetHookDir(WCHAR *out, size_t cch) {
    WCHAR appdata[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        WCHAR tmp[MAX_PATH] = {0};
        GetTempPathW(MAX_PATH, tmp);
        _snwprintf(out, cch, L"%sScanning\\hook", tmp);
        return;
    }
    _snwprintf(out, cch, L"%s\\Scanning\\hook", appdata);
}

static void EnsureLogDir(void) {
    WCHAR dir[MAX_PATH] = {0};
    GetHookDir(dir, MAX_PATH);
    WCHAR parent[MAX_PATH] = {0};
    wcsncpy(parent, dir, MAX_PATH - 1);
    WCHAR *slash = wcsrchr(parent, L'\\');
    if (slash) {
        *slash = 0;
        CreateDirectoryW(parent, NULL);
    }
    CreateDirectoryW(dir, NULL);
}

static void BuildLogPath(void) {
    WCHAR dir[MAX_PATH] = {0};
    GetHookDir(dir, MAX_PATH);
    _snwprintf(g_log_path, MAX_PATH, L"%s\\scanning_hook.log", dir);
}

static void HookLog(const char *fmt, ...) {
    if (g_log_path[0] == 0) {
        return;
    }
    LONG line = InterlockedIncrement(&g_log_lines);
    if (line > HOOK_LOG_LIMIT) {
        return;
    }
    if (g_lock_ready) {
        EnterCriticalSection(&g_lock);
    }
    FILE *fp = _wfopen(g_log_path, L"a");
    if (fp) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d.%03d [pid=%lu] ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                st.wMilliseconds, (unsigned long)g_pid);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
        fputc('\n', fp);
        fclose(fp);
    }
    if (g_lock_ready) {
        LeaveCriticalSection(&g_lock);
    }
}

static void ReadIniString(const WCHAR *section, const WCHAR *key,
                          const WCHAR *fallback, WCHAR *out, DWORD cch) {
    WCHAR dir[MAX_PATH] = {0};
    GetHookDir(dir, MAX_PATH);
    WCHAR path[MAX_PATH] = {0};
    _snwprintf(path, MAX_PATH, L"%s\\scanning_hook.ini", dir);
    DWORD n = GetPrivateProfileStringW(section, key, fallback, out, cch, path);
    if (n == 0) {
        wcsncpy(out, fallback, cch - 1);
    }
}

static void ParsePorts(const WCHAR *text) {
    g_port_count = 0;
    const WCHAR *p = text;
    while (*p && g_port_count < HOOK_MAX_PORTS) {
        while (*p == L' ' || *p == L'\t' || *p == L',') {
            p++;
        }
        if (*p == 0) {
            break;
        }
        WCHAR *end = NULL;
        long value = wcstol(p, &end, 10);
        if (end == p) {
            break;
        }
        if (value > 0 && value <= 65535) {
            g_ports[g_port_count++] = (int)value;
        }
        p = end;
    }
    if (g_port_count == 0) {
        g_ports[0] = 80;
        g_ports[1] = 443;
        g_port_count = 2;
    }
}

static BOOL ParseProxy(const WCHAR *text) {
    WCHAR host[256] = {0};
    int port = 0;
    const WCHAR *p = text;
    if (*p == L'[') {
        p++;
        const WCHAR *close = wcschr(p, L']');
        if (!close) {
            return FALSE;
        }
        size_t len = (size_t)(close - p);
        if (len >= 256) {
            return FALSE;
        }
        wcsncpy(host, p, len);
        host[len] = 0;
        if (close[1] != L':') {
            return FALSE;
        }
        port = (int)wcstol(close + 2, NULL, 10);
        g_proxy_is_v6 = TRUE;
    } else {
        const WCHAR *colon = wcsrchr(p, L':');
        if (!colon) {
            return FALSE;
        }
        size_t len = (size_t)(colon - p);
        if (len >= 256) {
            return FALSE;
        }
        wcsncpy(host, p, len);
        host[len] = 0;
        port = (int)wcstol(colon + 1, NULL, 10);
    }
    if (port <= 0 || port > 65535) {
        return FALSE;
    }
    CHAR hostA[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, host, -1, hostA, sizeof(hostA), NULL, NULL);
    if (g_proxy_is_v6) {
        if (InetPtonA(AF_INET6, hostA, &g_proxy_v6) != 1) {
            return FALSE;
        }
    } else {
        if (InetPtonA(AF_INET, hostA, &g_proxy_v4) != 1) {
            return FALSE;
        }
    }
    g_proxy_port = (USHORT)port;
    return TRUE;
}

// ---------------------------------------------------------------------------
// 模块导入表扫描与 IAT 替换
// ---------------------------------------------------------------------------

static BOOL IsConnectSlot(ULONG_PTR value) {
    return g_real_connect != NULL && value == (ULONG_PTR)g_real_connect;
}

static BOOL IsWsaConnectSlot(ULONG_PTR value) {
    return g_real_wsaconnect != NULL && value == (ULONG_PTR)g_real_wsaconnect;
}

static BOOL IsWsaIoctlSlot(ULONG_PTR value) {
    return g_real_wsaioc != NULL && value == (ULONG_PTR)g_real_wsaioc;
}

static int PatchThunkArray(BYTE *base, SIZE_T size, DWORD rva,
                           LONGLONG *patched) {
    if (rva == 0 || rva >= size) {
        return 0;
    }
    IMAGE_THUNK_DATA *thunks = (IMAGE_THUNK_DATA *)(base + rva);
    for (int i = 0; i < 4096; i++) {
        if ((BYTE *)(thunks + i + 1) > base + size) {
            break;
        }
        ULONG_PTR value = (ULONG_PTR)thunks[i].u1.Function;
        if (value == 0) {
            break;
        }
        void *target = NULL;
        if (IsConnectSlot(value)) {
            target = (void *)Hook_connect;
        } else if (IsWsaConnectSlot(value)) {
            target = (void *)Hook_WSAConnect;
        } else if (IsWsaIoctlSlot(value)) {
            target = (void *)Hook_WSAIoctl;
        }
        if (!target) {
            continue;
        }
        DWORD oldProtect = 0;
        if (VirtualProtect(&thunks[i].u1.Function, sizeof(ULONG_PTR),
                           PAGE_READWRITE, &oldProtect)) {
            InterlockedExchangePointer((PVOID volatile *)&thunks[i].u1.Function,
                                       target);
            VirtualProtect(&thunks[i].u1.Function, sizeof(ULONG_PTR),
                           oldProtect, &oldProtect);
            (*patched)++;
        }
    }
    return 0;
}

static void PatchDelayImports(BYTE *base, SIZE_T size,
                              IMAGE_DELAYLOAD_DESCRIPTOR *desc,
                              LONGLONG *patched) {
    for (int i = 0; i < 256; i++, desc++) {
        if (desc->DllNameRVA == 0 && desc->ImportAddressTableRVA == 0) {
            break;
        }
        if ((BYTE *)(desc + 1) > base + size) {
            break;
        }
        DWORD iatRva = desc->ImportAddressTableRVA;
        if ((desc->Attributes.AllAttributes & 1) == 0) {
            // 老式 VA 形式，本场景极少出现，跳过以免误写。
            continue;
        }
        PatchThunkArray(base, size, iatRva, patched);
    }
}

static void PatchModule(HMODULE module, const WCHAR *name) {
    BYTE *base = (BYTE *)module;
    if (base == NULL || base == (BYTE *)g_self) {
        return;
    }
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return;
    }
    SIZE_T size = nt->OptionalHeader.SizeOfImage;
    IMAGE_DATA_DIRECTORY *dirs = nt->OptionalHeader.DataDirectory;
    LONGLONG patched = 0;

    DWORD impRva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva != 0 && impRva < size) {
        IMAGE_IMPORT_DESCRIPTOR *desc =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + impRva);
        for (int i = 0; i < 512; i++, desc++) {
            if ((BYTE *)(desc + 1) > base + size) {
                break;
            }
            if (desc->Name == 0 && desc->FirstThunk == 0) {
                break;
            }
            PatchThunkArray(base, size, desc->FirstThunk, &patched);
        }
    }

    DWORD delayRva = dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    if (delayRva != 0 && delayRva < size) {
        PatchDelayImports(base, size, (IMAGE_DELAYLOAD_DESCRIPTOR *)(base + delayRva),
                          &patched);
    }

    if (patched > 0) {
        CHAR nameA[260] = {0};
        WideCharToMultiByte(CP_UTF8, 0, name, -1, nameA, sizeof(nameA), NULL, NULL);
        HookLog("patched %lld IAT entr%s in %s", (long long)patched,
                patched == 1 ? "y" : "ies", nameA);
    }
}

static void ScanModules(void) {
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        return;
    }
    MODULEENTRY32W entry;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snap, &entry)) {
        do {
            PatchModule(entry.hModule, entry.szModule);
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
// 套接字辅助
// ---------------------------------------------------------------------------

static BOOL IsPortWatched(USHORT port) {
    int value = (int)port; // 调用方传入的是主机字节序端口
    for (int i = 0; i < g_port_count; i++) {
        if (g_ports[i] == value) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsNonRoutableAddress(const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        ULONG host = ntohl(a->sin_addr.S_un.S_addr);
        if (host == 0 || host == 0x7f000001) {
            return TRUE;
        }
        if ((host & 0xff000000UL) == 0x7f000000UL) {
            return TRUE;
        }
        if ((host & 0xf0000000UL) == 0xe0000000UL) {
            return TRUE;
        }
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&a->sin6_addr)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL SocketIsBoundToNonLoopback(SOCKET s) {
    struct sockaddr_storage local;
    int len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) != 0) {
        return FALSE;
    }
    if (local.ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)&local;
        if (a->sin_port == 0) {
            return FALSE;
        }
        ULONG host = ntohl(a->sin_addr.S_un.S_addr);
        if (host != 0 && (host & 0xff000000UL) != 0x7f000000UL) {
            return TRUE;
        }
    } else if (local.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&local;
        if (a->sin6_port == 0) {
            return FALSE;
        }
        if (!IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr) &&
            !IN6_IS_ADDR_LOOPBACK(&a->sin6_addr)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int WaitSocket(SOCKET s, BOOL forWrite, int timeoutMs) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int rc = select(0, forWrite ? NULL : &set, forWrite ? &set : NULL, NULL, &tv);
    if (rc == SOCKET_ERROR) {
        return -1;
    }
    return rc;
}

static int ConnectSocket(SOCKET s, const struct sockaddr *addr, int addrLen,
                         int timeoutMs) {
    int rc = g_real_connect(s, addr, addrLen);
    if (rc == 0) {
        return 0;
    }
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        return err;
    }
    int n = WaitSocket(s, TRUE, timeoutMs);
    if (n == 0) {
        return WSAETIMEDOUT;
    }
    if (n < 0) {
        return WSAGetLastError();
    }
    int soError = 0;
    int soLen = sizeof(soError);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soError, &soLen) != 0) {
        return WSAGetLastError();
    }
    return soError;
}

static int SendAll(SOCKET s, const char *data, int len, int timeoutMs) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, len - sent, 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                int wait = WaitSocket(s, TRUE, timeoutMs);
                if (wait == 0) {
                    return WSAETIMEDOUT;
                }
                if (wait < 0) {
                    return WSAGetLastError();
                }
                continue;
            }
            if (err == WSAEINTR) {
                continue;
            }
            return err;
        }
        if (n == 0) {
            return WSAECONNRESET;
        }
        sent += n;
    }
    return 0;
}

static int RecvHeaders(SOCKET s, char *buf, int cap, int timeoutMs) {
    int len = 0;
    while (len < cap - 1) {
        int n = recv(s, buf + len, cap - 1 - len, 0);
        if (n > 0) {
            len += n;
            buf[len] = 0;
            if (strstr(buf, "\r\n\r\n") != NULL) {
                return len;
            }
            continue;
        }
        if (n == 0) {
            return WSAECONNRESET;
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            int wait = WaitSocket(s, FALSE, timeoutMs);
            if (wait == 0) {
                return WSAETIMEDOUT;
            }
            if (wait < 0) {
                return WSAGetLastError();
            }
            continue;
        }
        if (err == WSAEINTR) {
            continue;
        }
        return err;
    }
    return WSAEMSGSIZE;
}

static void FormatTarget(const struct sockaddr *addr, char *host, size_t hostCap,
                         char *target, size_t targetCap, USHORT *portOut) {
    host[0] = 0;
    target[0] = 0;
    *portOut = 0;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        InetNtopA(AF_INET, (void *)&a->sin_addr, host, (DWORD)hostCap);
        *portOut = ntohs(a->sin_port);
        _snprintf(target, targetCap, "%s:%u", host, (unsigned)*portOut);
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&a->sin6_addr)) {
            struct in_addr v4;
            memcpy(&v4, &a->sin6_addr.s6_addr[12], 4);
            InetNtopA(AF_INET, &v4, host, (DWORD)hostCap);
            *portOut = ntohs(a->sin6_port);
            _snprintf(target, targetCap, "%s:%u", host, (unsigned)*portOut);
        } else {
            char raw[INET6_ADDRSTRLEN] = {0};
            InetNtopA(AF_INET6, (void *)&a->sin6_addr, raw, sizeof(raw));
            _snprintf(host, hostCap, "%s", raw);
            *portOut = ntohs(a->sin6_port);
            _snprintf(target, targetCap, "[%s]:%u", raw, (unsigned)*portOut);
        }
    }
}

static int BuildProxySockaddr(int family, struct sockaddr_storage *out,
                              int *outLen) {
    memset(out, 0, sizeof(*out));
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(g_proxy_port);
        if (g_proxy_is_v6) {
            a->sin6_addr = g_proxy_v6;
        } else {
            a->sin6_addr.s6_addr[10] = 0xff;
            a->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&a->sin6_addr.s6_addr[12], &g_proxy_v4, 4);
        }
        *outLen = sizeof(struct sockaddr_in6);
        return 0;
    }
    if (family == AF_INET) {
        if (g_proxy_is_v6) {
            return WSAEAFNOSUPPORT;
        }
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET;
        a->sin_port = htons(g_proxy_port);
        a->sin_addr = g_proxy_v4;
        *outLen = sizeof(struct sockaddr_in);
        return 0;
    }
    return WSAEAFNOSUPPORT;
}

static BOOL ShouldRedirect(const struct sockaddr *addr, int addrLen,
                           char *target, size_t targetCap, USHORT *port) {
    if (addr == NULL || addrLen <= 0) {
        return FALSE;
    }
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return FALSE;
    }
    if (IsNonRoutableAddress(addr)) {
        return FALSE;
    }
    char host[INET6_ADDRSTRLEN] = {0};
    FormatTarget(addr, host, sizeof(host), target, targetCap, port);
    if (*port == 0 || !IsPortWatched(*port)) {
        return FALSE;
    }
    // 避免把发往代理自身的连接再次重定向。
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        if (!g_proxy_is_v6 && a->sin_addr.S_un.S_addr == g_proxy_v4.S_un.S_addr &&
            ntohs(a->sin_port) == g_proxy_port) {
            return FALSE;
        }
    } else if (addr->sa_family == AF_INET6 && g_proxy_is_v6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        if (memcmp(&a->sin6_addr, &g_proxy_v6, sizeof(g_proxy_v6)) == 0 &&
            ntohs(a->sin6_port) == g_proxy_port) {
            return FALSE;
        }
    }
    return TRUE;
}

// 在客户端 socket 上完成“改接到本机代理 + HTTP CONNECT 握手”。
static int RedirectConnect(SOCKET s, const struct sockaddr *addr, int addrLen) {
    USHORT port = 0;
    char target[320] = {0};
    if (!ShouldRedirect(addr, addrLen, target, sizeof(target), &port)) {
        return -1;
    }
    if (SocketIsBoundToNonLoopback(s)) {
        HookLog("skip bound socket target=%s", target);
        return -1;
    }

    struct sockaddr_storage proxyAddr;
    int proxyLen = 0;
    int buildErr = BuildProxySockaddr(addr->sa_family, &proxyAddr, &proxyLen);
    if (buildErr != 0) {
        HookLog("proxy family unsupported target=%s error=%d", target, buildErr);
        return buildErr;
    }

    int rc = ConnectSocket(s, (struct sockaddr *)&proxyAddr, proxyLen,
                           HOOK_CONNECT_TIMEOUT_MS);
    if (rc != 0) {
        HookLog("proxy connect failed target=%s error=%d", target, rc);
        return rc;
    }

    char request[640];
    int requestLen = _snprintf(request, sizeof(request),
                               "CONNECT %s HTTP/1.1\r\n"
                               "Host: %s\r\n"
                               "X-Scanning-Hook: 1\r\n"
                               "X-Scanning-Pid: %lu\r\n"
                               "\r\n",
                               target, target, (unsigned long)g_pid);
    if (requestLen <= 0 || requestLen >= (int)sizeof(request)) {
        return WSAEFAULT;
    }
    rc = SendAll(s, request, requestLen, HOOK_CONNECT_TIMEOUT_MS);
    if (rc != 0) {
        HookLog("CONNECT send failed target=%s error=%d", target, rc);
        return rc;
    }

    char response[HOOK_HEADER_LIMIT];
    rc = RecvHeaders(s, response, sizeof(response), HOOK_CONNECT_TIMEOUT_MS);
    if (rc <= 0) {
        HookLog("CONNECT response failed target=%s error=%d", target, rc);
        return rc > 0 ? WSAECONNRESET : rc;
    }
    if (rc < 12 || memcmp(response, "HTTP/", 5) != 0 ||
        response[9] != '2' || response[10] != '0' || response[11] != '0') {
        HookLog("CONNECT rejected target=%s response=%.80s", target, response);
        return WSAECONNREFUSED;
    }

    LONG count = InterlockedIncrement(&g_redirect_count);
    if (count <= 200 || count % 100 == 0) {
        HookLog("redirected target=%s count=%ld", target, (long)count);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 网络 API detour
// ---------------------------------------------------------------------------

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (!g_enabled || name == NULL) {
        return g_real_connect(s, name, namelen);
    }
    LONG callNo = InterlockedIncrement(&g_connect_calls);
    if (callNo <= 20) {
        char debugHost[INET6_ADDRSTRLEN] = {0};
        char debugTarget[320] = {0};
        USHORT debugPort = 0;
        if (name->sa_family == AF_INET || name->sa_family == AF_INET6) {
            FormatTarget(name, debugHost, sizeof(debugHost), debugTarget,
                         sizeof(debugTarget), &debugPort);
        }
        HookLog("connect intercepted family=%d target=%s port=%u call=%ld",
                name->sa_family, debugTarget, (unsigned)debugPort, (long)callNo);
    }
    int rc = RedirectConnect(s, name, namelen);
    if (rc == -1) {
        return g_real_connect(s, name, namelen);
    }
    if (rc == 0) {
        return 0;
    }
    WSASetLastError(rc);
    return SOCKET_ERROR;
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name,
                                  int namelen, LPWSABUF callerData,
                                  LPWSABUF calleeData, LPQOS sqos, LPQOS gqos) {
    // 带 callerData 的 WSAConnect 会在连接完成后立即发送数据，不能在这里插入
    // CONNECT 握手，否则会破坏应用协议；退化为原始调用。
    if (callerData != NULL && callerData->len > 0) {
        return g_real_wsaconnect(s, name, namelen, callerData, calleeData, sqos, gqos);
    }
    if (!g_enabled || name == NULL) {
        return g_real_wsaconnect(s, name, namelen, callerData, calleeData, sqos, gqos);
    }
    int rc = RedirectConnect(s, name, namelen);
    if (rc == -1) {
        return g_real_wsaconnect(s, name, namelen, callerData, calleeData, sqos, gqos);
    }
    if (rc == 0) {
        return 0;
    }
    WSASetLastError(rc);
    return SOCKET_ERROR;
}

static void CompleteOverlapped(LPOVERLAPPED ov, DWORD bytes, int err) {
    if (ov == NULL) {
        return;
    }
    ov->Internal = (ULONG_PTR)err;
    ov->InternalHigh = (ULONG_PTR)bytes;
    if (err == 0 && ov->hEvent != NULL) {
        SetEvent(ov->hEvent);
    }
}

static int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen,
                                LPVOID outBuf, DWORD outLen, LPDWORD bytes,
                                LPWSAOVERLAPPED ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (code == SIO_GET_EXTENSION_FUNCTION_POINTER && inBuf != NULL &&
        outBuf != NULL && inLen >= sizeof(GUID) && outLen >= sizeof(void *)) {
        if (memcmp(inBuf, &kConnectExGuid, sizeof(GUID)) == 0) {
            *(FN_CONNECT_EX *)outBuf = Hook_ConnectEx;
            if (bytes != NULL) {
                *bytes = sizeof(void *);
            }
            HookLog("provided ConnectEx detour socket=%llu",
                    (unsigned long long)s);
            return 0;
        }
    }
    return g_real_wsaioc(s, code, inBuf, inLen, outBuf, outLen, bytes, ov, cr);
}

static BOOL WSAAPI Hook_ConnectEx(SOCKET s, const struct sockaddr *name,
                                  int namelen, PVOID sendBuf, DWORD sendLen,
                                  LPDWORD bytesSent, LPOVERLAPPED ov) {
    if (!g_enabled || name == NULL) {
        if (g_real_connectex != NULL) {
            return g_real_connectex(s, name, namelen, sendBuf, sendLen, bytesSent, ov);
        }
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    int rc = RedirectConnect(s, name, namelen);
    if (rc == -1) {
        if (g_real_connectex != NULL) {
            return g_real_connectex(s, name, namelen, sendBuf, sendLen, bytesSent, ov);
        }
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (rc != 0) {
        CompleteOverlapped(ov, 0, rc);
        WSASetLastError(rc);
        HookLog("ConnectEx redirect failed error=%d", rc);
        return FALSE;
    }
    DWORD sent = 0;
    if (sendBuf != NULL && sendLen > 0) {
        int sendErr = SendAll(s, (const char *)sendBuf, (int)sendLen,
                              HOOK_CONNECT_TIMEOUT_MS);
        if (sendErr != 0) {
            CompleteOverlapped(ov, 0, sendErr);
            WSASetLastError(sendErr);
            HookLog("ConnectEx initial send failed error=%d", sendErr);
            return FALSE;
        }
        sent = sendLen;
    }
    if (bytesSent != NULL) {
        *bytesSent = sent;
    }
    CompleteOverlapped(ov, sent, 0);
    return TRUE;
}

// ---------------------------------------------------------------------------
// CFG 与初始化
// ---------------------------------------------------------------------------

static void RegisterCfgTarget(void *fn) {
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel || !fn) {
        return;
    }
    PFN_SetProcessValidCallTargets setTargets =
        (PFN_SetProcessValidCallTargets)GetProcAddress(
            kernel, "SetProcessValidCallTargets");
    if (!setTargets) {
        return;
    }
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    ULONG_PTR pageSize = si.dwPageSize;
    ULONG_PTR base = (ULONG_PTR)fn & ~(pageSize - 1);
    SCANNING_CFG_CALL_TARGET_INFO info;
    info.Offset = (ULONG_PTR)fn - base;
    info.Flags = CFG_CALL_TARGET_VALID;
    setTargets(GetCurrentProcess(), (PVOID)base, pageSize, 1, &info);
}

static DWORD WINAPI BackgroundThread(LPVOID param) {
    (void)param;
    g_pid = GetCurrentProcessId();

    EnsureLogDir();
    BuildLogPath();
    InitializeCriticalSection(&g_lock);
    g_lock_ready = TRUE;

    WCHAR proxyText[256] = L"127.0.0.1:8899";
    WCHAR portsText[128] = L"80,443";
    ReadIniString(L"hook", L"proxy", L"127.0.0.1:8899", proxyText, 256);
    ReadIniString(L"hook", L"ports", L"80,443", portsText, 128);

    WSADATA wsa;
    int wsaErr = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaErr != 0) {
        HookLog("WSAStartup failed error=%d", wsaErr);
        return 0;
    }

    g_real_connect = (FN_CONNECT)GetProcAddress(
        GetModuleHandleW(L"ws2_32.dll"), "connect");
    g_real_wsaconnect = (FN_WSA_CONNECT)GetProcAddress(
        GetModuleHandleW(L"ws2_32.dll"), "WSAConnect");
    g_real_wsaioc = (FN_WSA_IOCTL)GetProcAddress(
        GetModuleHandleW(L"ws2_32.dll"), "WSAIoctl");
    if (!g_real_connect) {
        HookLog("resolve connect failed");
        return 0;
    }
    HMODULE mswsock = LoadLibraryW(L"mswsock.dll");
    if (mswsock != NULL) {
        g_real_connectex = (FN_CONNECT_EX)GetProcAddress(mswsock, "ConnectEx");
    }
    if (g_real_connectex == NULL && g_real_wsaioc != NULL) {
        SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (probe != INVALID_SOCKET) {
            GUID guid = kConnectExGuid;
            void *fn = NULL;
            DWORD bytes = 0;
            if (g_real_wsaioc(probe, SIO_GET_EXTENSION_FUNCTION_POINTER,
                              &guid, sizeof(guid), &fn, sizeof(fn), &bytes,
                              NULL, NULL) == 0) {
                g_real_connectex = (FN_CONNECT_EX)fn;
            }
            closesocket(probe);
        }
    }

    if (!ParseProxy(proxyText)) {
        HookLog("invalid proxy config, fallback to 127.0.0.1:8899");
        g_proxy_is_v6 = FALSE;
        InetPtonA(AF_INET, "127.0.0.1", &g_proxy_v4);
        g_proxy_port = 8899;
    }
    ParsePorts(portsText);

    RegisterCfgTarget((void *)Hook_connect);
    RegisterCfgTarget((void *)Hook_WSAConnect);
    RegisterCfgTarget((void *)Hook_WSAIoctl);
    RegisterCfgTarget((void *)Hook_ConnectEx);

    CHAR proxyA[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, proxyText, -1, proxyA, sizeof(proxyA), NULL, NULL);
    HookLog("hook initialized pid=%lu proxy=%s ports=%d real_connect=%p wsaioc=%p connectex=%p",
            (unsigned long)g_pid, proxyA, g_port_count, (void *)g_real_connect,
            (void *)g_real_wsaioc, (void *)g_real_connectex);

    /* 首次 IAT 扫描完成后通知注入器，替代固定时长休眠。 */
    WCHAR ready_name[64] = {0};
    _snwprintf(ready_name, 63, L"Local\\ScanningHookReady_%lu", (unsigned long)g_pid);
    g_ready_event = CreateEventW(NULL, TRUE, FALSE, ready_name);

    ScanModules();
    if (g_ready_event != NULL) {
        SetEvent(g_ready_event);
        HookLog("hook ready signalled pid=%lu", (unsigned long)g_pid);
    }

    for (int i = 0; i < 10; i++) {
        Sleep(200);
        ScanModules();
    }
    g_enabled = TRUE;
    HookLog("hook enabled pid=%lu", (unsigned long)g_pid);

    for (;;) {
        Sleep(2000);
        ScanModules();
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = hinst;
        DisableThreadLibraryCalls(hinst);
        HANDLE th = CreateThread(NULL, 0, BackgroundThread, NULL, 0, NULL);
        if (th) {
            CloseHandle(th);
        }
    }
    return TRUE;
}
