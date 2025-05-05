#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <vector>
#include <thread>
#include <filesystem>
#include <map>
#include <unordered_map>
#include <chrono>
#include <random>
#include <mutex>
#include "Update.hpp"

#include <intrin.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "oxorany_include.h"
#include <winhttp.h>
#include <Psapi.h>
#include <cstring>
#include <cstdlib>  // for rand()/srand()
#include <tuple>
#include <winternl.h>  // for ProcessBasicInformation

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Psapi.lib")

// NT Status success definition
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// --- CFG Bypass Constants ---
#define CFG_IDENTITY             0xbff1e47f
#define CFG_PAGE_HASH_KEY        0x7b822ce4
#define CFG_VALIDATION_XOR       0x11

// --- CFG Hash Functions ---
#define HashPage(Page)           ((static_cast<uintptr_t>(Page) >> 0xC) ^ CFG_PAGE_HASH_KEY)
#define ValidationByte(Page)     ((((uintptr_t)(Page) >> 0x2C) ^ CFG_VALIDATION_XOR))

// Global synchronization objects
CRITICAL_SECTION g_ProtectionCS;
std::vector<DWORD> g_ProtectedThreads;
std::unordered_map<DWORD, CONTEXT> g_ThreadContexts;
std::mutex g_ThreadMutex;

// Thread hiding functions using direct NtSetInformationThread syscall
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

// Define ThreadHideFromDebugger
#define ThreadHideFromDebugger 0x11

// Forward declaration for functions used in BatchWhitelistRegion
bool SyscallRemoteCall(HANDLE hProcess, uintptr_t fnInsert, uintptr_t mapAddr, uint32_t identity, uint64_t hash);

// Syscall numbers from ntdll.dll for direct syscalls
#define SYSCALL_NTCREATETHREADEX 0xBA
#define SYSCALL_NTSETCONTEXTTHREAD 0xBE
#define SYSCALL_NTGETCONTEXTTHREAD 0xBF
#define SYSCALL_NTSETINFORMATIONTHREAD 0xC0
#define SYSCALL_NTSUSPENDTHREAD 0xC1
#define SYSCALL_NTRESUMETHREAD 0xC2

// Direct syscall function typedefs
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartRoutine,
    IN LPVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN LPVOID AttributeList);

typedef NTSTATUS(NTAPI* pNtSetContextThread)(
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext);

typedef NTSTATUS(NTAPI* pNtGetContextThread)(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT ThreadContext);

// --- CFG Batch Whitelist Region ---
static inline void BatchWhitelistRegion(HANDLE hProcess, uintptr_t insertFn, uintptr_t mapAddr, uintptr_t Start, size_t Size) {
    uintptr_t AlignedStart = Start & 0xfffffffffffff000;
    uintptr_t AlignedEnd = (Start + Size + 0xfff) & 0xfffffffffffff000;
    uint32_t Identity = CFG_IDENTITY;
    BYTE gsFlag = 0;

    // Read GS byte from TEB
    {
        auto gsAddr = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
        ReadProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr), &gsFlag, 1, nullptr);
    }

    if (!(gsFlag & 0x10)) {
        BYTE newFlag = gsFlag | 0x10;
        auto gsAddr2 = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
        WriteProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr2), &newFlag, 1, nullptr);
    }

    for (uintptr_t Page = AlignedStart; Page < AlignedEnd; Page += 0x1000) {
        uint64_t hash = static_cast<uint64_t>((Page >> 0xC) ^ CFG_PAGE_HASH_KEY);
        bool success = false;
        for (int attempt = 0; attempt < 5 && !success; ++attempt) {
            success = SyscallRemoteCall(hProcess, insertFn, mapAddr, CFG_IDENTITY, hash);
            if (!success) Sleep(50);
        }
    }

    BYTE finalFlag = gsFlag & ~0x10;
    auto gsAddr3 = static_cast<uintptr_t>(__readgsqword(0x30)) + 0x2EC;
    WriteProcessMemory(hProcess, reinterpret_cast<void*>(gsAddr3), &finalFlag, 1, nullptr);
}

// --- Bitmap Cache Patch ---
void PatchCFGCache(HANDLE hProcess, uintptr_t cacheBase, uintptr_t Base, size_t Size)
{
    uintptr_t alignedBase = Base & ~0xFFFF;
    size_t alignedSize = ((Size + 0xFFFF) / 0x10000) * 0x10000;

    for (uintptr_t offset = 0; offset < alignedSize; offset += 0x10000)
    {
        uintptr_t page = alignedBase + offset;
        uintptr_t entry = cacheBase + (page >> 0x13);
        uint32_t bit = 1 << (((page >> 0x10) & 7) % 32);
        uint32_t current = 0;

        ReadProcessMemory(hProcess, (LPCVOID)entry, &current, sizeof(current), nullptr);
        current |= bit;
        WriteProcessMemory(hProcess, (LPVOID)entry, &current, sizeof(current), nullptr);
    }
}

// Thread management class for advanced thread manipulation
class ThreadManager {
private:
    HANDLE m_ProcessHandle;
    uintptr_t m_DllBase;
    size_t m_DllSize;
    std::vector<HANDLE> m_ManagedThreads;
    std::vector<uintptr_t> m_EntryPoints;
    std::mutex m_ThreadLock;

    // Dynamic function pointers
    pNtSetInformationThread fnNtSetInformationThread;
    pNtCreateThreadEx fnNtCreateThreadEx;
    pNtSetContextThread fnNtSetContextThread;
    pNtGetContextThread fnNtGetContextThread;

    // Random number generator for stealth
    std::mt19937 m_RandGen;
    std::uniform_int_distribution<> m_RandDist;

public:
    ThreadManager(HANDLE hProcess, uintptr_t dllBase, size_t dllSize)
        : m_ProcessHandle(hProcess), m_DllBase(dllBase), m_DllSize(dllSize),
        m_RandGen(std::random_device()()),
        m_RandDist(100, 500) {

        // Initialize dynamic function pointers
        HMODULE ntdll = GetModuleHandleA(oxorany("ntdll.dll"));
        if (ntdll) {
            fnNtSetInformationThread = (pNtSetInformationThread)GetProcAddress(ntdll, oxorany("NtSetInformationThread"));
            fnNtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, oxorany("NtCreateThreadEx"));
            fnNtSetContextThread = (pNtSetContextThread)GetProcAddress(ntdll, oxorany("NtSetContextThread"));
            fnNtGetContextThread = (pNtGetContextThread)GetProcAddress(ntdll, oxorany("NtGetContextThread"));
        }

        // Find all possible entry points in the DLL
        FindEntryPoints();
    }

    ~ThreadManager() {
        // Cleanup all managed threads
        std::lock_guard<std::mutex> lock(m_ThreadLock);
        for (HANDLE hThread : m_ManagedThreads) {
            if (hThread && hThread != INVALID_HANDLE_VALUE) {
                CloseHandle(hThread);
            }
        }
        m_ManagedThreads.clear();
    }

    // Find multiple valid entry points for thread creation
    void FindEntryPoints() {
        // Always add DLL entry point
        IMAGE_DOS_HEADER dosHeader = {};
        IMAGE_NT_HEADERS ntHeaders = {};

        if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)m_DllBase, &dosHeader, sizeof(dosHeader), nullptr) &&
            dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {

            if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)(m_DllBase + dosHeader.e_lfanew),
                &ntHeaders, sizeof(ntHeaders), nullptr)) {

                // Add main entry point
                uintptr_t entryPoint = m_DllBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
                m_EntryPoints.push_back(entryPoint);

                // Try to find exported functions
                if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
                    IMAGE_EXPORT_DIRECTORY exportDir = {};
                    uintptr_t exportDirAddr = m_DllBase +
                        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

                    if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)exportDirAddr,
                        &exportDir, sizeof(exportDir), nullptr)) {

                        // Get function addresses
                        std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);
                        uintptr_t functionAddr = m_DllBase + exportDir.AddressOfFunctions;

                        if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)functionAddr,
                            functionRVAs.data(), functionRVAs.size() * sizeof(DWORD), nullptr)) {

                            for (DWORD rva : functionRVAs) {
                                if (rva) {
                                    uintptr_t funcAddr = m_DllBase + rva;
                                    m_EntryPoints.push_back(funcAddr);
                                }
                            }
                        }
                    }
                }

                // If we still don't have alternative entry points, scan for potential function starts
                if (m_EntryPoints.size() < 3) {
                    // Scan for common function prologues (e.g., push rbp, mov rbp, rsp)
                    BYTE buffer[4096];
                    for (size_t offset = 0; offset < m_DllSize; offset += sizeof(buffer) - 16) {
                        SIZE_T bytesRead = 0;
                        if (ReadProcessMemory(m_ProcessHandle, (LPCVOID)(m_DllBase + offset),
                            buffer, sizeof(buffer), &bytesRead) && bytesRead > 16) {

                            for (size_t i = 0; i < bytesRead - 16; i++) {
                                // Check for function prologue patterns
                                if ((buffer[i] == 0x55 && buffer[i + 1] == 0x48 && buffer[i + 2] == 0x89 && buffer[i + 3] == 0xE5) || // push rbp; mov rbp, rsp
                                    (buffer[i] == 0x48 && buffer[i + 1] == 0x83 && buffer[i + 2] == 0xEC) || // sub rsp, X
                                    (buffer[i] == 0x40 && buffer[i + 1] == 0x53) || // push rbx
                                    (buffer[i] == 0x48 && buffer[i + 1] == 0x89 && buffer[i + 2] == 0x5C && buffer[i + 3] == 0x24)) { // mov [rsp+X], rbx

                                    uintptr_t funcAddr = m_DllBase + offset + i;
                                    m_EntryPoints.push_back(funcAddr);

                                    // Skip ahead to avoid finding too many false positives
                                    i += 16;
                                }
                            }
                        }
                    }
                }
            }
        }

        // If we found some entry points, print them
        if (!m_EntryPoints.empty()) {
            printf("[+] Found %zu potential thread entry points\n", m_EntryPoints.size());
        }
        else {
            // Fallback: Just use the DLL base as entry point
            m_EntryPoints.push_back(m_DllBase);
            printf("[!] Using DLL base as entry point: %p\n", (void*)m_DllBase);
        }
    }

    // Hide a thread from debuggers and other detection mechanisms
    bool HideThread(HANDLE hThread) {
        if (!m_ProcessHandle || !hThread) return false;

        ULONG hiddenInfo = 0x01;
        NTSTATUS status = 0xC0000001;  // 0xC0000001 is the value of STATUS_UNSUCCESSFUL

        // Set thread hiding from debugger 
        if (fnNtSetInformationThread) {
            status = fnNtSetInformationThread(
                hThread,
                0x11,       // ThreadHideFromDebugger
                NULL,
                0
            );

            // Set critical thread - extreme protection, system will BSOD if thread is killed
            // Use with caution!
            NTSTATUS statusCritical = fnNtSetInformationThread(
                hThread,
                0x1E,       // ThreadBreakOnTermination
                &hiddenInfo,
                sizeof(hiddenInfo)
            );

            // Spoof thread start address to evade detection
            PVOID kernelDllBase = GetModuleHandleA("kernelbase.dll");
            if (kernelDllBase) {
                PVOID fakeStartAddress = (PVOID)((ULONG_PTR)kernelDllBase + 0x12345);
                fnNtSetInformationThread(
                    hThread,
                    9,        // ThreadQuerySetWin32StartAddress
                    &fakeStartAddress,
                    sizeof(fakeStartAddress)
                );
            }
        }

        // Set highest thread priority to make it more resistant to freezes
        SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

        // Assign to a specific processor core to improve performance and stability
        DWORD_PTR processAffinityMask = 0, systemAffinityMask = 0;
        if (GetProcessAffinityMask(GetCurrentProcess(), &processAffinityMask, &systemAffinityMask)) {
            // Find a good core to run on - prefer second core if available
            DWORD_PTR affinityMask = (processAffinityMask & 2) ? 2 : 1;
            SetThreadAffinityMask(hThread, affinityMask);
        }

        return NT_SUCCESS(status);
    }

    // Create a hidden thread at one of the entry points
    HANDLE CreateHiddenThread(uintptr_t entryPoint = 0, LPVOID param = NULL) {
        if (!m_ProcessHandle || !fnNtCreateThreadEx) return NULL;

        // If no entry point provided, pick a random one
        if (entryPoint == 0) {
            if (m_EntryPoints.empty()) return NULL;

            size_t index = rand() % m_EntryPoints.size();
            entryPoint = m_EntryPoints[index];
        }

        HANDLE hThread = NULL;

        // Use NtCreateThreadEx to create the thread with stealth flags
        // 0x00000004 = THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
        // 0x00000001 = THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        NTSTATUS status = fnNtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            m_ProcessHandle,
            (LPTHREAD_START_ROUTINE)entryPoint,
            param,
            0x00000004,  // Hide from debugger flag
            0,
            0,
            0,
            NULL
        );

        if (NT_SUCCESS(status) && hThread) {
            // Store the thread handle
            std::lock_guard<std::mutex> lock(m_ThreadLock);
            m_ManagedThreads.push_back(hThread);

            // Hide the thread more thoroughly
            HideThread(hThread);

            printf("[+] Created hidden thread at %p with handle %p\n", (void*)entryPoint, hThread);
            return hThread;
        }

        return NULL;
    }

    // Revive threads that have been terminated or suspended
    bool ReviveThreads(bool forceNewThreads = false) {
        bool createdAny = false;
        std::vector<HANDLE> deadThreads;
        bool needsConsoleThread = false;

        {
            std::lock_guard<std::mutex> lock(m_ThreadLock);

            // Check currently managed threads
            for (auto it = m_ManagedThreads.begin(); it != m_ManagedThreads.end();) {
                HANDLE hThread = *it;
                DWORD exitCode = 0;

                if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE) {
                    // Thread is dead, mark it for recreation
                    deadThreads.push_back(hThread);
                    it = m_ManagedThreads.erase(it);
                    printf("[!] Thread Manager: Dead thread detected, will recreate\n");
                    // Flush stdout to ensure message appears even if printing stops
                    fflush(stdout);
                    needsConsoleThread = true;
                }
                else {
                    // Thread is alive, check if it's suspended
                    if (fnNtGetContextThread && fnNtSetContextThread) {
                        CONTEXT ctx = { 0 };
                        ctx.ContextFlags = CONTEXT_CONTROL;

                        if (NT_SUCCESS(fnNtGetContextThread(hThread, &ctx))) {
                            // First, double-check RIP to ensure it's in our DLL
                            if (ctx.Rip < m_DllBase || ctx.Rip >= m_DllBase + m_DllSize) {
                                // Thread is not in our DLL - attempt to force it back in
                                for (const auto& entryPoint : m_EntryPoints) {
                                    if (entryPoint != 0) {
                                        // Try to redirect to one of our entry points
                                        ctx.Rip = entryPoint;
                                        // Apply the context change
                                        fnNtSetContextThread(hThread, &ctx);
                                        printf("[!] Thread Manager: Redirected thread back to DLL entry point\n");
                                        // Flush stdout to ensure message appears
                                        fflush(stdout);
                                        break;
                                    }
                                }
                            }

                            // Thread might be suspended, try to resume it
                            DWORD suspendCount = SuspendThread(hThread);
                            if (suspendCount > 0) {
                                printf("[!] Thread Manager: Found suspended thread, resuming (count=%d)\n", suspendCount);
                                // Flush stdout to ensure message appears
                                fflush(stdout);

                                // Resume the thread immediately
                                while (suspendCount > 0) {
                                    ResumeThread(hThread);
                                    suspendCount--;
                                }
                                // Extra resume to be safe
                                ResumeThread(hThread);
                            }
                            else {
                                // Thread not suspended, resume our query
                                ResumeThread(hThread);
                            }
                        }
                    }
                    ++it;
                }
            }
        }

        // Recreate dead threads with new entry points
        for (HANDLE hDeadThread : deadThreads) {
            CloseHandle(hDeadThread);

            // Create a new thread at a different entry point
            HANDLE hNewThread = CreateHiddenThread();
            if (hNewThread) {
                createdAny = true;
                printf("[+] Thread Manager: Successfully recreated dead thread\n");
                fflush(stdout); // Ensure immediate output
            }
        }

        // If forced or we have too few active threads, create more - increased minimum from 3 to 5
        if (forceNewThreads || m_ManagedThreads.size() < 5 || needsConsoleThread) {
            for (int i = 0; i < 5 - m_ManagedThreads.size(); i++) {
                HANDLE hNewThread = CreateHiddenThread();
                if (hNewThread) {
                    createdAny = true;
                    printf("[+] Thread Manager: Created additional thread\n");
                    fflush(stdout); // Ensure immediate output
                }
            }

            // If we detected console issues, create a dedicated console thread
            if (needsConsoleThread) {
                // This creates a thread specifically dedicated to handling console I/O
                HANDLE hConsoleThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                    ThreadManager* mgr = (ThreadManager*)param;

                    // Continuously ensure console is working
                    while (true) {
                        // Print a heartbeat message every few seconds
                        printf("[*] Console handler: Heartbeat check - %u\n", GetTickCount());
                        fflush(stdout);

                        // Reopen stdout if it appears to be closed
                        if (ferror(stdout)) {
                            clearerr(stdout);
                            freopen("CONOUT$", "w", stdout);
                            printf("[!] Console handler: Reopened stdout\n");
                            fflush(stdout);
                        }

                        // Sleep for a while before next check
                        Sleep(2000);
                    }

                    return 0;
                    }, this, 0, nullptr);

                if (hConsoleThread) {
                    printf("[+] Thread Manager: Created dedicated console handler thread\n");
                    fflush(stdout);
                    CloseHandle(hConsoleThread); // We don't need to track this handle
                }
            }
        }

        return createdAny;
    }

    // Get count of active managed threads
    size_t GetActiveThreadCount() {
        std::lock_guard<std::mutex> lock(m_ThreadLock);
        return m_ManagedThreads.size();
    }

    // Find all threads in the target process that are executing our DLL
    std::vector<DWORD> FindThreadsInDll() {
        std::vector<DWORD> threadIds;
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(m_ProcessHandle));

        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32 = { sizeof(THREADENTRY32) };

            if (Thread32First(hThreadSnap, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == GetProcessId(m_ProcessHandle)) {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            CONTEXT ctx = { 0 };
                            ctx.ContextFlags = CONTEXT_CONTROL;

                            if (GetThreadContext(hThread, &ctx)) {
                                if (ctx.Rip >= m_DllBase && ctx.Rip < m_DllBase + m_DllSize) {
                                    // Thread is executing in our DLL
                                    threadIds.push_back(te32.th32ThreadID);
                                }
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te32));
            }
            CloseHandle(hThreadSnap);
        }

        return threadIds;
    }

    // Advanced anti-detection: modify thread information to avoid detection patterns
    void CamouflageThreads() {
        std::lock_guard<std::mutex> lock(m_ThreadLock);

        for (HANDLE hThread : m_ManagedThreads) {
            // Various anti-detection measures can be implemented here

            // 1. Change thread start address information (fake address)
            if (fnNtSetInformationThread) {
                // Use undocumented thread information classes to modify metadata
                // ThreadQuerySetWin32StartAddress = 9
                uintptr_t fakeStartAddress = 0;

                // Pick a random system DLL address to masquerade as
                HMODULE hMods[100];
                DWORD cbNeeded;
                if (EnumProcessModules(m_ProcessHandle, hMods, sizeof(hMods), &cbNeeded)) {
                    // Get a random loaded module that isn't our DLL
                    for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        MODULEINFO modInfo;
                        if (GetModuleInformation(m_ProcessHandle, hMods[i], &modInfo, sizeof(modInfo))) {
                            if ((uintptr_t)modInfo.lpBaseOfDll != m_DllBase) {
                                // Use a random offset into this legitimate module
                                fakeStartAddress = (uintptr_t)modInfo.lpBaseOfDll + (rand() % (int)modInfo.SizeOfImage);
                                break;
                            }
                        }
                    }
                }

                if (fakeStartAddress) {
                    fnNtSetInformationThread(hThread, 9, &fakeStartAddress, sizeof(fakeStartAddress));
                }
            }

            // 2. Add random stack data to confuse stack walkers
            if (fnNtGetContextThread && fnNtSetContextThread) {
                CONTEXT ctx = { 0 };
                ctx.ContextFlags = CONTEXT_FULL;

                if (NT_SUCCESS(fnNtGetContextThread(hThread, &ctx))) {
                    // Save the original context
                    std::lock_guard<std::mutex> tlock(g_ThreadMutex);
                    g_ThreadContexts[GetThreadId(hThread)] = ctx;

                    // We don't actually want to modify the context now - just saved it for recovery
                }
            }
        }
    }

    // Restore original contexts for threads that might have been manipulated by anti-cheat
    void RestoreThreadContexts() {
        std::lock_guard<std::mutex> tlock(g_ThreadMutex);

        for (const auto& pair : g_ThreadContexts) {
            DWORD threadId = pair.first;
            const CONTEXT& savedCtx = pair.second;

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
            if (hThread) {
                // Check current context
                CONTEXT currentCtx = { 0 };
                currentCtx.ContextFlags = CONTEXT_CONTROL;

                if (GetThreadContext(hThread, &currentCtx)) {
                    // If RIP has been moved outside our DLL but was previously in it, restore it
                    if (currentCtx.Rip < m_DllBase || currentCtx.Rip >= m_DllBase + m_DllSize) {
                        if (savedCtx.Rip >= m_DllBase && savedCtx.Rip < m_DllBase + m_DllSize) {
                            // Suspend to modify context
                            SuspendThread(hThread);

                            // Restore saved context
                            SetThreadContext(hThread, &savedCtx);

                            // Resume thread with restored context
                            ResumeThread(hThread);
                            printf("[+] Restored thread %u context to RIP: %p\n", threadId, (void*)savedCtx.Rip);
                        }
                    }
                }
                CloseHandle(hThread);
            }
        }
    }
};

// Create a global ThreadManager instance
ThreadManager* g_ThreadManager = nullptr;

// Global handles for protection guardians (for mutual watchdog)
static HANDLE g_hGuard1 = NULL;
static HANDLE g_hGuard2 = NULL;
static HANDLE g_hGuard3 = NULL;
static HANDLE g_hGuard4 = NULL;
static HANDLE g_hGuard5 = NULL;
static HANDLE g_hGuard7 = NULL;
static HANDLE g_hGuard8 = NULL;
static HANDLE g_hGuard9 = NULL;
static HANDLE g_hGuard11 = NULL;
static HANDLE g_hGuard13 = NULL;
static HANDLE g_hSupervisor = NULL;

// Supervisor thread: monitors guardian threads and logs any that exit
static DWORD WINAPI SupervisorProc(LPVOID lp) {
    srand((unsigned)GetTickCount());
    struct GuardInfo { HANDLE h; const char* name; } guards[] = {
        {g_hGuard1, "Guardian1"},
        {g_hGuard2, "Guardian2"},
        {g_hGuard3, "Guardian3"},
        {g_hGuard4, "Guardian4"},
        {g_hGuard5, "Guardian5"},
        {g_hGuard7, "Guardian7"},
        {g_hGuard8, "Guardian8"},
        {g_hGuard9, "Guardian9"},
        {g_hGuard11, "Guardian11"},
        {g_hGuard13, "Guardian13"}
    };
    const int count = sizeof(guards) / sizeof(guards[0]);
    while (true) {
        Sleep(1000 + rand() % 500);
        for (int i = 0; i < count; ++i) {
            if (guards[i].h) {
                DWORD code = 0;
                if (GetExitCodeThread(guards[i].h, &code) && code != STILL_ACTIVE) {
                    printf("[!] Supervisor: %s has exited (code: %u)\n", guards[i].name, code);
                }
            }
        }
    }
    return 0;
}

// New thread management initialization function
void InitThreadManagement(HANDLE hProcess, uintptr_t dllBase, size_t dllSize) {
    InitializeCriticalSection(&g_ProtectionCS);
    g_ThreadManager = new ThreadManager(hProcess, dllBase, dllSize);

    // Initial thread creation
    for (int i = 0; i < 3; i++) {
        g_ThreadManager->CreateHiddenThread();
    }

    // Camouflage the threads
    g_ThreadManager->CamouflageThreads();
}

// Thread management cleanup function
void CleanupThreadManagement() {
    if (g_ThreadManager) {
        delete g_ThreadManager;
        g_ThreadManager = nullptr;
    }
    DeleteCriticalSection(&g_ProtectionCS);
}

#pragma region SCF Constants & Utility

using Stk_t = void**;

static std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);

    if (!stream.is_open()) {
        return {};
    }

    size_t fileSize = static_cast<size_t>(stream.tellg());
    stream.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);

    if (!stream.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        return {};
    }

    return buffer;
}

#define SCF_WRAP_START _Pragma("optimize(\"\", off)")
#define SCF_WRAP_END _Pragma("optimize(\"\", on)")

#define SCF_END goto __scf_skip_end;__debugbreak();__halt();__scf_skip_end:{};
#define SCF_STACK *const_cast<Stk_t*>(&__scf_ptr_stk);
#define SCF_START const Stk_t __scf_ptr_stk = reinterpret_cast<const Stk_t>(Offsets::SCF_MARKER_STK); Stk_t Stack = SCF_STACK;

constexpr uint64_t ceil_div(uint64_t Number, uint64_t Divisor) {
    return Number / Divisor + (Number % Divisor > 0);
}

template<typename T = uint64_t, size_t Size, size_t Items = ceil_div(Size, sizeof(T))>
constexpr std::array<T, Items> to_integer(const char(&Str)[Size]) {
    std::array<T, Items> result = { 0 };

    for (size_t i = 0; i < Size; ++i) {
        result[i / sizeof(T)] |= static_cast<T>(Str[i]) << (8 * (i % sizeof(T)));
    }

    return result;
}

#define STK_STRING(Name, String)										\
constexpr auto _buf_##Name = to_integer<uint64_t>(String);					\
const char* ##Name = reinterpret_cast<const char*>(&_buf_##Name);

template<typename RetType, typename ...Args>
struct SelfContained {
    union {
        void* Page = nullptr;
        RetType(*Function)(Args...); /* used for LOCAL testing */
    };
    size_t Size = 0;

    void* HData = nullptr;
    HANDLE Target = INVALID_HANDLE_VALUE;

    SelfContained() = default;
    SelfContained(void* Page, size_t Size) : Page(Page), Size(Size) {}
    SelfContained(uintptr_t Page, size_t Size) : Page(reinterpret_cast<void*>(Page)), Size(Size) {}
};
uintptr_t baseAddress = 0;

struct FunctionData {
    void* Page;
    size_t Size;
};
#pragma endregion

#define Offset(Base, Length) reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Base) + Length)

class Exception : public std::runtime_error {
public:
    Exception(const std::string& Message)
        : std::runtime_error(Message + " failed with: " + std::to_string(GetLastError()))
    {
    }
    Exception(const std::string& Message, const std::string& Detail)
        : std::runtime_error(Message + " failed with: " + Detail)
    {
    }
};

namespace Process {
    struct Module {
        uint32_t Size = 0;
        uintptr_t Start = 0;
        uintptr_t End = 0;
        HANDLE Target = INVALID_HANDLE_VALUE;
        std::string Name = "";
        std::map<std::string, void*> Exports = {};

        __forceinline void* GetAddress(std::string Name) {
            if (Exports.find(Name) == Exports.end()) {
                return nullptr;
            }
            return Exports[Name];
        }
    };

    namespace details {
#pragma region Memory Utility
        template<typename T = void*, typename AddrType = void*>
        __forceinline T RemoteAlloc(HANDLE Handle, size_t Size = sizeof(T), uint32_t ProtectionType = PAGE_EXECUTE_READWRITE, uint32_t AllocationType = MEM_COMMIT | MEM_RESERVE) {
            void* Address = VirtualAllocEx(Handle, nullptr, Size, AllocationType, ProtectionType);

            if (!Address) {
                throw Exception(oxorany("VirtualAllocEx"));
            }

            return reinterpret_cast<T>(Address);
        }

        template<typename AddrType = void*>
        __forceinline void RemoteFree(HANDLE Handle, AddrType Address, size_t Size = 0, uint32_t FreeType = MEM_RELEASE) {
            bool Success = VirtualFreeEx(Handle, Address, Size, FreeType);
            if (!Success) {
                throw Exception(oxorany("VirtualFreeEx"));
            }
        }

        template<typename T = void*, typename AddrType = void*>
        __forceinline void RemoteWrite(HANDLE Handle, AddrType Address, T Buffer, size_t Size = sizeof(T)) {
            size_t Count = 0;
            bool Success = WriteProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                throw Exception(oxorany("WriteProcessMemory"));
            }

            if (Count != Size) {
                throw Exception(oxorany("WriteProcessMemory"), oxorany("Partial write"));
            }
        }

        template<typename AddrType = void*>
        __forceinline uint32_t RemoteProtect(HANDLE Handle, AddrType Address, size_t Size, uint32_t ProtectionType, bool* StatusOut = nullptr) {
            DWORD OriginalProtection = 0;
            bool Success = VirtualProtectEx(Handle, (void*)Address, Size, ProtectionType, &OriginalProtection);

            if (StatusOut) {
                *StatusOut = Success;
            }
            else if (!Success) {
                throw Exception(oxorany("VirtualAllocEx"));
            }

            return OriginalProtection;
        }

        template<typename T, typename AddrType = void*>
        __forceinline T RemoteRead(HANDLE Handle, AddrType Address, size_t Size = sizeof(T)) {
            void* Buffer = std::malloc(Size);

            if (!Buffer) {
                throw std::bad_alloc();
            }

            size_t Count = 0;
            bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                throw Exception(oxorany("ReadProcessMemory"));
            }

            if (Count != Size) {
                throw Exception(oxorany("ReadProcessMemory"), oxorany("Partial read"));
            }

            T Result = {};
            std::memcpy(&Result, Buffer, Size);
            std::free(Buffer);
            return Result;
        }

        template<typename T, typename AddrType = void*>
        __forceinline void RemoteRead(HANDLE Handle, AddrType Address, T* Buffer, size_t Size = sizeof(T)) {
            size_t Count = 0;
            bool Success = ReadProcessMemory(Handle, reinterpret_cast<void*>(Address), Buffer, Size, &Count);

            if (!Success) {
                throw Exception(oxorany("ReadProcessMemory"));
            }

            if (Count != Size) {
                throw Exception(oxorany("ReadProcessMemory"), oxorany("Partial read"));
            }
        }

        template<typename AddrType = void*>
        __forceinline std::string ReadString(HANDLE Handle, AddrType Address, size_t Length = 0) {
            std::string Result = {};
            Result.resize(Length);

            uintptr_t Current = reinterpret_cast<uintptr_t>(Address);
            if (Length == 0) {
                char TempBuffer[16] = {};
                while (true) {
                    if (Result.size() > 10000) {
                        throw Exception(oxorany("ReadString"), oxorany("Possible infinite loop"));
                    }

                    RemoteRead(Handle, Current, TempBuffer, sizeof(TempBuffer));
                    Current += sizeof(TempBuffer);

                    size_t Len = strnlen(TempBuffer, 16);
                    Result.append(TempBuffer, Len);

                    if (Len != 16) {
                        break;
                    }
                }
            }
            else {
                char* TempBuffer = new char[Length];
                RemoteRead(Handle, Current, TempBuffer, Length);
                Result.assign(TempBuffer, Length);
                delete[] TempBuffer;
            }

            return Result;
        }
#pragma endregion

#pragma region Process & Module Utility
        static HANDLE OpenSnapshot(uint32_t Flags, uint32_t Id, int maxRetries = 20) {
            HANDLE Snapshot = CreateToolhelp32Snapshot(Flags, Id);
            int retryCount = 0;

            while (Snapshot == INVALID_HANDLE_VALUE) {
                DWORD lastError = GetLastError();
                if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_INVALID_PARAMETER) {
                    std::cerr << oxorany("Snapshot failed GAY: ") << lastError << std::endl;
                    return INVALID_HANDLE_VALUE;
                }

                if (lastError == ERROR_BAD_LENGTH && Flags == TH32CS_SNAPMODULE || Flags == TH32CS_SNAPMODULE32) {
                    Snapshot = CreateToolhelp32Snapshot(Flags, Id);
                    continue;
                }

                std::cerr << oxorany("Snapshot failed GAY: ") << lastError << oxorany(". Retrying i guess");

                if (++retryCount >= maxRetries) {
                    std::cerr << oxorany("Max Retries I GIVE UP") << std::endl;
                    return INVALID_HANDLE_VALUE;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                Snapshot = CreateToolhelp32Snapshot(Flags, Id);
            }

            return Snapshot;
        }

        static uint32_t _FindProcessByName(std::wstring Name) {
            uint32_t HighestCount = 0;
            uint32_t ProcessId = 0;

            HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPPROCESS, 0);

            PROCESSENTRY32W Entry = {};
            Entry.dwSize = sizeof(Entry);

            if (!Process32First(Snapshot, &Entry)) {
                CloseHandle(Snapshot);
                throw std::runtime_error(oxorany("Failed to find first Process."));
            }

            do {
                if (Name == std::wstring(Entry.szExeFile) && Entry.cntThreads > HighestCount) {
                    HighestCount = Entry.cntThreads;
                    ProcessId = Entry.th32ProcessID;
                }
            } while (Process32Next(Snapshot, &Entry));

            CloseHandle(Snapshot);
            return ProcessId;
        }

        static void UpdateExports(Module& Data) {
            void* Base = (void*)Data.Start;
            HANDLE Handle = Data.Target;

            if (Base == nullptr) {
                return;
            }

            IMAGE_DOS_HEADER DosHeader = details::RemoteRead<IMAGE_DOS_HEADER>(Handle, Base);

            if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                throw Exception(oxorany("UpdateExports"), oxorany("Invalid DosHeader"));
            }

            IMAGE_NT_HEADERS64 NtHeaders = RemoteRead<IMAGE_NT_HEADERS64>(Handle, Offset(Base, DosHeader.e_lfanew));
            IMAGE_DATA_DIRECTORY ExportDataDirectory = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!ExportDataDirectory.VirtualAddress) {
                return;
            }
            if (!ExportDataDirectory.Size) {
                return;
            }
            IMAGE_EXPORT_DIRECTORY ExportDirectory = RemoteRead<IMAGE_EXPORT_DIRECTORY>(Handle, Offset(Base, ExportDataDirectory.VirtualAddress));

            DWORD NumberOfNames = ExportDirectory.NumberOfNames;
            DWORD NumberOfFunctions = ExportDirectory.NumberOfFunctions;

            void* AddressOfFunctions = Offset(Base, ExportDirectory.AddressOfFunctions);
            void* AddressOfNames = Offset(Base, ExportDirectory.AddressOfNames);
            void* AddressOfNameOrdinals = Offset(Base, ExportDirectory.AddressOfNameOrdinals);

            std::vector<DWORD> NameRVAs = {};
            NameRVAs.resize(NumberOfNames);
            RemoteRead<DWORD>(Handle, AddressOfNames, NameRVAs.data(), NumberOfNames * sizeof(DWORD));

            std::vector<WORD> OrdinalsRVAs = {};
            OrdinalsRVAs.resize(NumberOfNames);
            RemoteRead<WORD>(Handle, AddressOfNameOrdinals, OrdinalsRVAs.data(), NumberOfNames * sizeof(WORD));

            std::vector<DWORD> FunctionRVAs = {};
            FunctionRVAs.resize(NumberOfFunctions);
            RemoteRead<DWORD>(Handle, AddressOfFunctions, FunctionRVAs.data(), NumberOfFunctions * sizeof(DWORD));

            size_t Index = 0;
            for (DWORD NameRVA : NameRVAs) {
                std::string NameString = ReadString(Handle, Offset(Base, NameRVA));
                WORD NameOrdinal = OrdinalsRVAs[Index];
                Data.Exports[NameString] = Offset(Base, FunctionRVAs[NameOrdinal]);
                Index++;
            }
        };

        static bool _FindModule(std::string Name, Module& Data, uint32_t Id, HANDLE Handle) {
            HANDLE Snapshot = OpenSnapshot(TH32CS_SNAPMODULE, Id);

            MODULEENTRY32 Entry = {};
            Entry.dwSize = sizeof(Entry);

            if (!Module32First(Snapshot, &Entry)) {
                CloseHandle(Snapshot);
                throw std::runtime_error(oxorany("Failed to find first Module."));
            }

            do {
                if (Entry.th32ProcessID != Id) {
                    continue;
                }

                std::filesystem::path Path(Entry.szExePath);

                if (Name == Path.filename().string()) {
                    Data.Name = Name;
                    Data.Size = Entry.modBaseSize;
                    Data.Target = Handle;
                    Data.Start = reinterpret_cast<uintptr_t>(Entry.modBaseAddr);
                    Data.End = Data.Start + Data.Size;
                    UpdateExports(Data);
                    CloseHandle(Snapshot);
                    return true;
                }
            } while (Module32Next(Snapshot, &Entry));

            CloseHandle(Snapshot);
            return false;
        }

        Module _WaitForModule(std::string Name, uint32_t Id, HANDLE Handle) {
            Module Data = {};

            while (!_FindModule(Name, Data, Id, Handle)) {}

            return Data;
        }

        static uint32_t _WaitForProcess(std::wstring Name) {
            uint32_t ProcessId = 0;
            while (!ProcessId) {
                try {
                    ProcessId = _FindProcessByName(Name);
                }
                catch (const std::runtime_error& ex) {
                    std::cerr << oxorany("FindProcess Exception: ") << ex.what() << std::endl;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return ProcessId;
        }
#pragma endregion
    }

    struct Object {
        HANDLE _handle = INVALID_HANDLE_VALUE;
        uint32_t _id = 0;

        Module GetModule(std::string Name) const {
            return details::_WaitForModule(Name, _id, _handle);
        }
    };

    static Object WaitForProcess(const std::wstring& Name) {
        uint32_t Id = details::_WaitForProcess(Name);
        HANDLE Handle = OpenProcess(PROCESS_ALL_ACCESS, false, Id);

        Object result;
        result._handle = Handle;
        result._id = Id;
        return result;
    }
}

namespace Injector {
    namespace details {
        template<typename T>
        __forceinline T LocalRead(const uint8_t* Bytes) {
            return *reinterpret_cast<T*>(const_cast<uint8_t*>(Bytes));
        }

        template<typename T>
        __forceinline void LocalWrite(const uint8_t* Bytes, T Value) {
            *reinterpret_cast<T*>(const_cast<uint8_t*>(Bytes)) = Value;
        }

        static __forceinline const size_t CalculateFunctionSize(void* Function) {
            uint8_t* Bytes = reinterpret_cast<uint8_t*>(Function);
            size_t Size = 0;

            while (LocalRead<uint32_t>(Bytes + Size) != Offsets::SCF_END_MARKER) {
                Size++;
            }

            const size_t kSize = Size;

            while (Size - kSize < 16) {
                switch (LocalRead<uint8_t>(Bytes + Size)) {
                case 0xCC: {
                    if (Size == kSize + 3) {
                        goto return_size;
                    }
                    break;
                }
                case 0xC2: {
                    Size += 3;
                    goto return_size;
                }
                case 0xC3: {
                    Size++;
                    goto return_size;
                }
                }

                Size++;
            }

        return_size:
            return Size;
        }

        static __forceinline const size_t CalculateStackSize(const std::vector<void*>& StackPointers, const size_t FunctionSize) {
            uintptr_t StackStart = FunctionSize + sizeof(void*);
            uintptr_t AlignedStackStart = StackStart + (StackStart % sizeof(void*));

            uintptr_t StackEnd = AlignedStackStart + (StackPointers.size() * sizeof(void*));

            return StackEnd - StackStart;
        }

        static __forceinline void* ReadJmpRel32(Process::Object& proc, void* Instruction) {
            int32_t RelativeOffset = Process::details::RemoteRead<int32_t>(proc._handle, Offset(Instruction, 1));
            return Offset(Offset(Instruction, 5), RelativeOffset);
        }

        static __forceinline void* ReadJmpM64(Process::Object& proc, void* Instruction) {
            return Process::details::RemoteRead<void*>(proc._handle, Offset(Instruction, 6));
        }

        static __forceinline void* WriteJmpM64(Process::Object& proc, void* Instruction, void* Target) {
            void* OldTarget = ReadJmpM64(proc, Instruction);

            uint32_t OldProtection = Process::details::RemoteProtect(proc._handle, Offset(Instruction, 6), sizeof(void*), PAGE_EXECUTE_READWRITE);
            Process::details::RemoteWrite<void*>(proc._handle, Offset(Instruction, 6), &Target);
            Process::details::RemoteProtect(proc._handle, Offset(Instruction, 6), sizeof(void*), OldProtection);
            return OldTarget;
        }
    }

    uintptr_t rebase(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address - baseAddress); //+0x400000
    }


    template<typename RetType, typename ...Args>
    SelfContained<RetType, Args...> CreateSCF(HANDLE Target, RetType(*Function)(Args...), const std::vector<void*>& kStackPointers) {
        std::vector<void*> StackPointers = {};
        StackPointers.reserve(kStackPointers.size() + 1);
        StackPointers.push_back(nullptr);

        for (void* Item : kStackPointers)
            StackPointers.push_back(Item);

        size_t FunctionSize = details::CalculateFunctionSize(Function);
        //printf("[*] Function Size: 0x%llx\n", FunctionSize);

        size_t StackSize = details::CalculateStackSize(StackPointers, FunctionSize);
        //printf("[*] Stack Size: 0x%llx\n", StackSize);

        size_t PageSize = FunctionSize + StackSize;
        //printf("[*] PageSize: 0x%llx\n", PageSize);

        uintptr_t PageAddr = Process::details::RemoteAlloc<uintptr_t>(Target, PageSize, PAGE_READWRITE);
        //printf("[*] PageAddr: 0x%llx\n", PageAddr);

        //printf("[*] Pushing FunctionData onto the Stack.\n");
        FunctionData HData;
        HData.Page = reinterpret_cast<void*>(PageAddr);
        HData.Size = PageSize;

        uintptr_t HDataAddr = Process::details::RemoteAlloc<uintptr_t>(Target, sizeof(FunctionData));
        Process::details::RemoteWrite(Target, HDataAddr, &HData, sizeof(FunctionData));

        StackPointers.front() = reinterpret_cast<void*>(HDataAddr);

        uintptr_t StackAddr = PageAddr + FunctionSize + sizeof(void*);
        //printf("[*] StackAddr: 0x%llx\n", StackAddr);

        StackAddr += (StackAddr % sizeof(void*));
        //printf("[*] Aligned StackAddr (Start): 0x%llx\n", StackAddr);
        uintptr_t StackStart = StackAddr;

        uint8_t* FunctionBytes = new uint8_t[FunctionSize];
        std::memcpy(FunctionBytes, Function, FunctionSize);

        //printf("[*] Local Function Buffer: %p\n", FunctionBytes);


        printf("[*] Bypasss.\n");
        for (uintptr_t Offset = 0; Offset < FunctionSize; Offset++) {
            uint8_t* CurrentBytes = FunctionBytes + Offset;

            if (details::LocalRead<uintptr_t>(CurrentBytes) == Offsets::SCF_MARKER_STK) {
                //printf("[*] - Found `SCF_MARKER_STK` at offset 0x%llx, overwriting with 0x%llx.\n", Offset, StackAddr);
                details::LocalWrite<uintptr_t>(CurrentBytes, StackAddr);

                Offset += sizeof(void*);
                continue;
            }


            if (details::LocalRead<uint32_t>(CurrentBytes) == Offsets::SCF_END_MARKER) {
                //printf("[*] - Found `SCF_END_MARKER` at offset 0x%llx, overwriting with NOP. \n", Offset);
                details::LocalWrite<uint32_t>(CurrentBytes, 0x90909090); // NOP

            }
        }


        //size_t RegionSize = PageSize;
        //baseAddress = PageAddr;
        //const auto cfg_cache = *reinterpret_cast<std::uintptr_t*>(rebase(0xbef9e0));

        //if (cfg_cache)
        //{
        //	uintptr_t base = 0x1000; // allocate a memory EXTERNALLY, internal allocation is detected..
        //	base &= -0x1000;
        //	for (auto pg = base; pg < base + RegionSize; pg += 0x1000)
        //		*reinterpret_cast<std::uint32_t*>(cfg_cache + (pg >> 0x13)) |= 1 << ((pg >> 0x10 & 7) % 0x20); // RARELY updates
        //}




        for (void* Item : StackPointers) {
            //printf("[*] Writing %p to Stack at address: 0x%llx.\n", Item, StackAddr);
            Process::details::RemoteWrite<void*>(Target, StackAddr, &Item);
            StackAddr += sizeof(void*);
        }

        printf("[*] Finishing.\n");

        Process::details::RemoteWrite(Target, PageAddr, FunctionBytes, FunctionSize);
        delete[] FunctionBytes;

        Process::details::RemoteProtect(Target, PageAddr, FunctionSize, PAGE_EXECUTE);

        SelfContained<RetType, Args...> Result = {};

        Result.Page = reinterpret_cast<void*>(PageAddr),
            Result.Size = PageSize;
        Result.HData = reinterpret_cast<void*>(HDataAddr);
        Result.Target = Target;

        return Result;
    }

    template<typename RetType, typename ...Args>
    void DestroySCF(SelfContained<RetType, Args...>& Data) {
        Process::details::RemoteFree(Data.Target, Data.Page, 0, MEM_RELEASE);
    }

    enum HOOK_STATUS {
        HOOK_IDLE,
        HOOK_RUNNING,
        HOOK_FINISHED,
        STATUS_1,
        STATUS_2,
        STATUS_3,
        STATUS_4,
        STATUS_5,
        STATUS_6,
        STATUS_7,
        STATUS_8,
        STATUS_9,
        STATUS_10,
        STATUS_11,
        STATUS_12,
        STATUS_13,
        STATUS_14,
        STATUS_15,
        STATUS_16,
        STATUS_17,
        STATUS_18,
        STATUS_19,
        STATUS_20,
    };

    const char* STATUSES[] = {
        "HOOK_IDLE",
        "HOOK_RUNNING",
        "HOOK_FINISHED",
        "STATUS_1",
        "STATUS_2",
        "STATUS_3",
        "STATUS_4",
        "STATUS_5",
        "STATUS_6",
        "STATUS_7",
        "STATUS_8",
        "STATUS_9",
        "STATUS_10",
        "STATUS_11",
        "STATUS_12",
        "STATUS_13",
        "STATUS_14",
        "STATUS_15",
        "STATUS_16",
        "STATUS_17",
        "STATUS_18",
        "STATUS_19",
        "STATUS_20",
    };

    template<typename RetType, typename ...Args>
    struct NtHook {
        void* Previous = nullptr;
        void* Status = nullptr;
        void* Stub = nullptr;
        Process::Object Target = {};
        SelfContained<RetType, Args...> Detour = {};
        NtHook() = default;
        NtHook(void* Previous, void* Status, void* Stub, SelfContained<RetType, Args...>& Detour) : Previous(Previous), Status(Status), Stub(Stub), Detour(Detour) {};
    };

    template<typename RetType, typename ...Args>
    NtHook<RetType, Args...> Hook(Process::Object& proc, const char* Name, RetType(*Detour)(Args...), const std::vector<void*>& ExtraStack) {
        Process::Module ntdll = proc.GetModule("ntdll.dll");

        void* Function = ntdll.GetAddress(Name);
        void* DynamicStub = Injector::details::ReadJmpRel32(proc, Function);
        void* Hook = Injector::details::ReadJmpM64(proc, DynamicStub);

        void* Status = Process::details::RemoteAlloc(proc._handle, sizeof(uint32_t), PAGE_READWRITE);
        auto Val = Injector::HOOK_IDLE;
        Process::details::RemoteWrite(proc._handle, Status, &Val);

        std::vector<void*> Stack = {
            Hook,
            Status
        };

        for (void* Item : ExtraStack) {
            Stack.push_back(Item);
        }

        auto SCF = Injector::CreateSCF(proc._handle, Detour, Stack);
        Injector::details::WriteJmpM64(proc, DynamicStub, SCF.Page);
        NtHook<RetType, Args...> Result = {};

        Result.Detour = SCF;
        Result.Previous = Hook;
        Result.Stub = DynamicStub;
        Result.Target = proc;
        Result.Status = Status;

        return Result;
    }

    template<typename RetType, typename ...Args>
    void Unhook(NtHook<RetType, Args...>& Data) {
        Injector::details::WriteJmpM64(Data.Target, Data.Stub, Data.Previous);
        FlushInstructionCache(Data.Target._handle, nullptr, 0);
        Process::details::RemoteFree(Data.Target._handle, Data.Status);
        Injector::DestroySCF(Data.Detour);
    }
}

namespace Types {
    using NtQuerySystemInformation = int32_t(__stdcall*)(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

    namespace unordered_set {
        using insert = void* (__fastcall*)(void*, void*, void*);
    }
};

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define HashPage(Page) reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(Page) >> Offsets::kPageShift) ^ Offsets::kPageHash)
#define WhitelistPage(Page) 
#define WhitelistRegion(Start, Size)

SCF_WRAP_START;
int32_t __stdcall NtQuerySystemInformation(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength) {
    SCF_START;

    FunctionData* DetourPage = reinterpret_cast<FunctionData*>(Stack[0]);
    auto Original = reinterpret_cast<Types::NtQuerySystemInformation>(Stack[1]);
    auto Status = reinterpret_cast<Injector::HOOK_STATUS*>(Stack[2]);
    auto insert_set = reinterpret_cast<Types::unordered_set::insert>(Stack[3]);
    void* memory_map = Stack[4];
    uintptr_t Base = reinterpret_cast<uintptr_t>(Stack[5]);
    auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(Stack[6]);
    auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(Stack[7]);
    auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(Stack[8]);
    HANDLE ProcessHandle = reinterpret_cast<HANDLE>(Stack[9]);


    if (*Status == Injector::HOOK_IDLE) {
        *Status = Injector::HOOK_RUNNING;

        // Skip whitelisting as we do it from the main process

        *Status = Injector::STATUS_3;
        auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
        auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Base + Dos->e_lfanew);
        auto* Opt = &Nt->OptionalHeader;
        auto Size = Opt->SizeOfImage;
        *Status = Injector::STATUS_4;

        *Status = Injector::STATUS_5;
        // Skip whitelisting here too
        *Status = Injector::STATUS_6;

        uintptr_t LocationDelta = Base - Opt->ImageBase;
        if (LocationDelta) {
            *Status = Injector::STATUS_7;
            IMAGE_DATA_DIRECTORY RelocDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (RelocDir.Size) {
                auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(Base + RelocDir.VirtualAddress);
                const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + RelocDir.Size);
                while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                    UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                    for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                        if (RELOC_FLAG(*pRelativeInfo)) {
                            UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(Base + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                            *pPatch += LocationDelta;
                        }
                    }
                    pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
                }
            }
            *Status = Injector::STATUS_8;
        }

        IMAGE_DATA_DIRECTORY ImportDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (ImportDir.Size) {
            *Status = Injector::STATUS_9;
            auto* ImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Base + ImportDir.VirtualAddress);
            while (ImportDescriptor->Name) {
                char* ModuleName = reinterpret_cast<char*>(Base + ImportDescriptor->Name);
                HMODULE Module = _GetModuleHandleA(ModuleName);

                if (!Module) {
                    Module = _LoadLibraryA(ModuleName);
                    if (!Module) {
                        ++ImportDescriptor;
                        continue;
                    }
                }

                uintptr_t* ThunkRefPtr = reinterpret_cast<uintptr_t*>(Base + ImportDescriptor->OriginalFirstThunk);
                uintptr_t* FuncRefPtr = reinterpret_cast<uintptr_t*>(Base + ImportDescriptor->FirstThunk);

                if (!ThunkRefPtr) {
                    ThunkRefPtr = FuncRefPtr;
                }

                uintptr_t ThunkRef;
                while (ThunkRef = *ThunkRefPtr) {
                    if (IMAGE_SNAP_BY_ORDINAL(ThunkRef)) {
                        *FuncRefPtr = (uintptr_t)_GetProcAddress(Module, reinterpret_cast<char*>(ThunkRef & 0xFFFF));
                    }
                    else {
                        IMAGE_IMPORT_BY_NAME* ImportData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(Base + ThunkRef);
                        *FuncRefPtr = (uintptr_t)_GetProcAddress(Module, ImportData->Name);
                    }
                    ++ThunkRefPtr;
                    ++FuncRefPtr;
                }
                ++ImportDescriptor;
            }
            *Status = Injector::STATUS_10;
        }

        IMAGE_DATA_DIRECTORY TlsDir = Opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (TlsDir.Size) {
            *Status = Injector::STATUS_11;
            auto* TlsData = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(Base + TlsDir.VirtualAddress);
            auto* CallbackArray = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TlsData->AddressOfCallBacks);
            while (CallbackArray && *CallbackArray) {
                PIMAGE_TLS_CALLBACK Callback = *CallbackArray;
                Callback(reinterpret_cast<void*>(Base), DLL_PROCESS_ATTACH, nullptr);
            }
            *Status = Injector::STATUS_12;
        }

        *Status = Injector::STATUS_13;
        auto DllMain = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(Base + Opt->AddressOfEntryPoint);
        *Status = Injector::STATUS_14;

        *Status = Injector::STATUS_15;
        DllMain(reinterpret_cast<HMODULE>(Base), DLL_PROCESS_ATTACH, nullptr);
        *Status = Injector::STATUS_16;

        *Status = Injector::HOOK_FINISHED;
    }

    return Original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    SCF_END;
}
SCF_WRAP_END;


SCF_WRAP_START;
int32_t __stdcall NtQuerySystemInformationOld(uint32_t SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength) {
    SCF_START;

    FunctionData* DetourPage = reinterpret_cast<FunctionData*>(Stack[0]);
    auto Original = reinterpret_cast<Types::NtQuerySystemInformation>(Stack[1]);
    auto Status = reinterpret_cast<Injector::HOOK_STATUS*>(Stack[2]);
    auto insert_set = reinterpret_cast<Types::unordered_set::insert>(Stack[3]);
    void* memory_map = Stack[4];
    uintptr_t Base = reinterpret_cast<uintptr_t>(Stack[5]);
    auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(Stack[6]);
    auto _GetModuleHandleA = reinterpret_cast<decltype(&GetModuleHandleA)>(Stack[7]);
    auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(Stack[8]);
    auto _MessageBoxA = reinterpret_cast<decltype(&MessageBoxA)>(Stack[9]);


    if (*Status == Injector::HOOK_IDLE) {
        *Status = Injector::HOOK_RUNNING;

        // Skip whitelisting as we do it from the main process
        *Status = Injector::STATUS_2;

        _MessageBoxA(nullptr, nullptr, nullptr, MB_OK | MB_ICONINFORMATION);

        *Status = Injector::HOOK_FINISHED;
    }

    return Original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    SCF_END;
}
SCF_WRAP_END;


#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BytesWritten);

extern "C" NTSTATUS NTAPI NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartRoutine,
    IN LPVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN LPVOID AttributeList);

bool SyscallRemoteCall(HANDLE hProcess, uintptr_t fnInsert, uintptr_t mapAddr, uint32_t identity, uint64_t hash) {
    uint8_t stub[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,    // mov rax, fnInsert
        0x48, 0xB9, 0,0,0,0,0,0,0,0,    // mov rcx, mapAddr
        0x48, 0xBA, 0,0,0,0,0,0,0,0,    // mov rdx, identityAddr
        0x49, 0xB8, 0,0,0,0,0,0,0,0,    // mov r8, hashAddr
        0xFF, 0xD0,                    // call rax
        0xC3                           // ret
    };

    uint8_t args[sizeof(uint32_t) + sizeof(uint64_t)]{};
    memcpy(args, &identity, sizeof(identity));
    memcpy(args + sizeof(identity), &hash, sizeof(hash));

    PVOID remoteArg = nullptr;
    SIZE_T argSize = 0x1000;
    if (NtAllocateVirtualMemory(hProcess, &remoteArg, 0, &argSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        return false;

    NtWriteVirtualMemory(hProcess, remoteArg, args, sizeof(args), nullptr);

    uintptr_t remoteIdentity = reinterpret_cast<uintptr_t>(remoteArg);
    uintptr_t remoteHash = remoteIdentity + sizeof(uint32_t);

    memcpy(&stub[2], &fnInsert, sizeof(uintptr_t));
    memcpy(&stub[12], &mapAddr, sizeof(uintptr_t));
    memcpy(&stub[22], &remoteIdentity, sizeof(uintptr_t));
    memcpy(&stub[32], &remoteHash, sizeof(uintptr_t));

    PVOID remoteCode = nullptr;
    SIZE_T codeSize = 0x1000;
    if (NtAllocateVirtualMemory(hProcess, &remoteCode, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != 0)
        return false;

    NtWriteVirtualMemory(hProcess, remoteCode, stub, sizeof(stub), nullptr);

    HANDLE hThread = nullptr;
    if (NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess, (LPTHREAD_START_ROUTINE)remoteCode, nullptr, 0, 0, 0, 0, nullptr) != 0)
        return false;

    WaitForSingleObject(hThread, INFINITE);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    CloseHandle(hThread);

    return code != 0;
}

HMODULE GetRemoteModuleHandle(HANDLE hProcess, const wchar_t* modName) {
    MODULEENTRY32W me32{};
    me32.dwSize = sizeof(MODULEENTRY32W);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

    if (Module32FirstW(hSnap, &me32)) {
        do {
            if (!_wcsicmp(me32.szModule, modName)) {
                CloseHandle(hSnap);
                return me32.hModule;
            }
        } while (Module32NextW(hSnap, &me32));
    }

    CloseHandle(hSnap);
    return nullptr;
}

namespace nbeater678_bypass {
    constexpr auto nbeater678_shift = 0xC;
    constexpr auto nbeater678_magic = CFG_PAGE_HASH_KEY;
    constexpr auto nbeater678_mask = 0xFFFF;
    constexpr auto nbeater678_align = 0x10000;

    // Add these type definitions at the beginning of the namespace
    using NtProtect_t = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static NtProtect_t pNtProtectStub = nullptr;

    // Private syscall stub loader for unhookable syscalls
    static void* LoadSyscallStub(const char* funcName, size_t stubSize = 16) {
        // Map clean ntdll.dll from disk
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), path, MAX_PATH)) {
            throw Exception("GetModuleFileNameW failed");
        }
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            throw Exception("CreateFileW ntdll.dll failed");
        }
        HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) {
            CloseHandle(hFile);
            throw Exception("CreateFileMappingW failed");
        }
        BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!base) {
            CloseHandle(hMap);
            CloseHandle(hFile);
            throw Exception("MapViewOfFile failed");
        }
        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        auto* expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        auto* names = reinterpret_cast<uint32_t*>(base + expDir->AddressOfNames);
        auto* ords = reinterpret_cast<uint16_t*>(base + expDir->AddressOfNameOrdinals);
        auto* funcs = reinterpret_cast<uint32_t*>(base + expDir->AddressOfFunctions);
        BYTE* stubSrc = nullptr;
        for (uint32_t i = 0; i < expDir->NumberOfNames; i++) {
            char* name = reinterpret_cast<char*>(base + names[i]);
            if (strcmp(name, funcName) == 0) {
                uint16_t ord = ords[i];
                uint32_t rva = funcs[ord];
                stubSrc = base + rva;
                break;
            }
        }
        if (!stubSrc) {
            UnmapViewOfFile(base);
            CloseHandle(hMap);
            CloseHandle(hFile);
            throw Exception("Export not found");
        }
        void* buf = VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(buf, stubSrc, stubSize);
        // Remove the VirtualProtect call that changes permissions to PAGE_EXECUTE_READ
        // DWORD oldProt;
        // VirtualProtect(buf, stubSize, PAGE_EXECUTE_READ, &oldProt);  
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return buf;
    }

    __forceinline uintptr_t nbeater678_crypt(uintptr_t addr) {
        return (uintptr_t)((addr >> nbeater678_shift) ^ nbeater678_magic);
    }

    void nbeater678_whitelist(HANDLE hProc, uintptr_t base, size_t len) {
        auto mod = GetRemoteModuleHandle(hProc, L"RobloxPlayerBeta.dll");
        if (!mod) return;

        // Use reinterpret_cast for HMODULE -> uintptr_t
        uintptr_t fn = reinterpret_cast<uintptr_t>(mod) + Offsets::set_insert;
        uintptr_t map = reinterpret_cast<uintptr_t>(mod) + Offsets::map;

        // Use BatchWhitelistRegion for more efficient implementation
        BatchWhitelistRegion(hProc, fn, map, base, len);

        // Fallback measures in case BatchWhitelistRegion fails
        uintptr_t low = base & ~0xFFF, high = (base + len + 0xFFF) & ~0xFFF;
        for (uintptr_t p = low; p < high; p += 0x1000) {
            auto h = nbeater678_crypt(p);
            bool ok = false;
            for (int t = 0; t < 3 && !ok; ++t) {
                ok = SyscallRemoteCall(hProc, fn, map, CFG_IDENTITY, h);
                if (!ok) Sleep(50);
            }
            if (!ok) {
                // Fallback: enforce RWX via VirtualProtectEx then unhookable NtProtect stub
                bool protOk = false;
                DWORD oldProt = 0;
                if (VirtualProtectEx(hProc, (LPVOID)p, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt)) {
                    protOk = true;
                }
                // Load direct syscall stub if needed
                if (!pNtProtectStub) {
                    pNtProtectStub = (NtProtect_t)LoadSyscallStub("NtProtectVirtualMemory");
                }
                if (pNtProtectStub) {
                    PVOID addrPtr = (PVOID)p;
                    SIZE_T sizePtr = 0x1000;
                    ULONG oldStubProt = 0;
                    // Ensure PAGE_EXECUTE_READWRITE is used
                    NTSTATUS st = pNtProtectStub(hProc, &addrPtr, &sizePtr, PAGE_EXECUTE_READWRITE, &oldStubProt);
                    if (NT_SUCCESS(st)) {
                        protOk = true;
                    }
                }
                if (protOk) {
                    printf("[!] Whitelist fallback: PAGE_EXECUTE_READWRITE enforced at %p\n", (void*)p);
                    FlushInstructionCache(hProc, (LPVOID)p, 0x1000);
                }
                else {
                    printf("[!] Whitelist fallback failed at %p (GetLastError = %u)\n", (void*)p, GetLastError());
                }
            }
        }
    }

    void nbeater678_cache(HANDLE hProc, uintptr_t base, size_t len) {
        auto mod = GetRemoteModuleHandle(hProc, L"RobloxPlayerBeta.dll");
        if (!mod) return;

        uintptr_t cbase = 0;
        if (!ReadProcessMemory(hProc, (void*)((uintptr_t)mod + Offsets::cfg_cachee), &cbase, sizeof(cbase), nullptr) || !cbase) return;

        // Use optimized PatchCFGCache implementation
        PatchCFGCache(hProc, cbase, base, len);
    }
}

// Add this new function for setting memory executable per-page
static bool SetDirectExecutable(HANDLE hProcess, uintptr_t base, size_t size) {
    printf("[+] Setting executable memory with direct VirtualProtectEx calls...\n");
    uintptr_t start = base & ~0xFFF;
    uintptr_t end = (base + size + 0xFFF) & ~0xFFF;
    size_t pageCount = (end - start) / 0x1000;
    size_t successCount = 0;

    for (uintptr_t addr = start; addr < end; addr += 0x1000) {
        DWORD oldProt = 0;
        // Always use PAGE_EXECUTE_READWRITE
        if (VirtualProtectEx(hProcess, (LPVOID)addr, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt)) {
            successCount++;
            // Touch the memory to ensure protection changes are applied
            BYTE buffer[4] = {};
            BYTE tmpBuf[4] = {};
            SIZE_T bytesRead = 0;
            ReadProcessMemory(hProcess, (LPVOID)addr, buffer, sizeof(buffer), &bytesRead);
            if (bytesRead) {
                WriteProcessMemory(hProcess, (LPVOID)addr, buffer, bytesRead, nullptr);
                FlushInstructionCache(hProcess, (LPVOID)addr, 0x1000);
            }
        }
    }

    printf("[+] Executable pages set: %zu/%zu\n", successCount, pageCount);

    // Verify success - check at least one page in each section
    bool anyExec = false;
    for (uintptr_t addr = start; addr < end; addr += 0x10000) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProcess, (LPVOID)addr, &mbi, sizeof(mbi))) {
            // Check for both execute and write permissions
            if ((mbi.Protect & PAGE_EXECUTE) && (mbi.Protect & PAGE_READWRITE)) {
                anyExec = true;
                printf("[+] Verified RWX at %p: 0x%X\n", (void*)addr, mbi.Protect);
                break;
            }
        }
    }

    return (successCount > 0) && anyExec;
}

bool ManualMap(Process::Object& proc, std::string Path) {
    Process::Module loader = proc.GetModule(oxorany("RobloxPlayerBeta.dll"));
    Process::Module kernelbase = proc.GetModule(oxorany("KERNELBASE.dll"));
    Process::Module user32 = proc.GetModule(oxorany("USER32.dll"));

#pragma region Write file into process
    std::vector<uint8_t> Data = ReadFile(Path);
    if (Data.empty()) {
        return false;
    }

    uint8_t* Buffer = Data.data();

    IMAGE_DOS_HEADER* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>(Buffer);
    IMAGE_NT_HEADERS* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>(Buffer + Dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER* OptHeader = &Nt->OptionalHeader;
    IMAGE_FILE_HEADER* FileHeader = &Nt->FileHeader;

    // Allocate memory with RWX permissions from the start
    uintptr_t TargetBase = Process::details::RemoteAlloc<uintptr_t>(proc._handle, OptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE);
    Process::details::RemoteWrite(proc._handle, TargetBase, Buffer, 0x1000);

    std::vector<IMAGE_SECTION_HEADER*> Sections = {};
    IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(Nt);
    for (uint32_t i = 0; i != FileHeader->NumberOfSections; ++i, ++SectionHeader) {
        if (SectionHeader->SizeOfRawData) {
            Sections.push_back(SectionHeader);
            Process::details::RemoteWrite(proc._handle, TargetBase + SectionHeader->VirtualAddress, Buffer + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
        }
    }
#pragma endregion

    // CRITICAL: Do extensive direct whitelisting before creating the hook
    printf("[*] Step 1: Whitelisting executable sections...\n");
    // Gather only executable sections
    std::vector<IMAGE_SECTION_HEADER*> execSecs;
    for (auto sec : Sections) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) execSecs.push_back(sec);
    }

    // Get necessary addresses for CFG bypass
    // Remove redundant cast as loader.Start is already uintptr_t
    uintptr_t fnInsert = loader.Start + Offsets::set_insert;
    uintptr_t mapAddr = loader.Start + Offsets::map;
    uintptr_t cfgCacheAddr = 0;
    // Remove redundant cast as loader.Start is already uintptr_t
    ReadProcessMemory(proc._handle, reinterpret_cast<void*>(loader.Start + Offsets::cfg_cachee), &cfgCacheAddr, sizeof(cfgCacheAddr), nullptr);

    // 1a: Bypass whitelist + cache per section
    bool allOk = true;
    for (auto sec : execSecs) {
        uintptr_t secBase = TargetBase + sec->VirtualAddress;
        size_t secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        printf("[*] Whitelisting section %.*s @ %p (0x%zx bytes)\n", 8, sec->Name, (void*)secBase, secSize);
        try {
            // Use the BatchWhitelistRegion macro for efficient whitelisting
            BatchWhitelistRegion(proc._handle, fnInsert, mapAddr, secBase, secSize);

            // Use PatchCFGCache for efficient cache patching
            if (cfgCacheAddr) {
                PatchCFGCache(proc._handle, cfgCacheAddr, secBase, secSize);
            }
        }
        catch (const std::exception& e) {
            allOk = false;
            printf("[!] Bypass error on %.*s: %s\n", 8, sec->Name, e.what());

            // Fallback to traditional methods
            nbeater678_bypass::nbeater678_whitelist(proc._handle, secBase, secSize);
            nbeater678_bypass::nbeater678_cache(proc._handle, secBase, secSize);
        }
    }

    // Also whitelist the entire image for safety
    printf("[*] Whitelisting entire image...\n");
    BatchWhitelistRegion(proc._handle, fnInsert, mapAddr, TargetBase, OptHeader->SizeOfImage);
    if (cfgCacheAddr) {
        PatchCFGCache(proc._handle, cfgCacheAddr, TargetBase, OptHeader->SizeOfImage);
    }

    // 6: Verification of protections
    printf("[*] Verification: checking random pages...\n");
    srand((unsigned)GetTickCount());
    for (auto sec : execSecs) {
        uintptr_t base = TargetBase + sec->VirtualAddress;
        size_t size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        uintptr_t testAddr = base + ((rand() % ((size + 0xFFF) / 0x1000)) * 0x1000);
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(proc._handle, (LPCVOID)testAddr, &mbi, sizeof(mbi))) {
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == 0) {
                printf("[!] Verification failed at %p: Protect=0x%x\n", (void*)testAddr, mbi.Protect);
            }
        }
    }

    // 3: Spawn whitelist guardian thread
    struct WLParams {
        HANDLE h;
        uintptr_t base;
        size_t size;
        uintptr_t insert;
        uintptr_t map;
        uintptr_t cache;
    };

    // Create a proper parameter struct
    auto* wl = new WLParams{
        proc._handle,
        TargetBase,
        OptHeader->SizeOfImage,
        fnInsert,
        mapAddr,
        cfgCacheAddr
    };

    // Create thread with proper parameter passing
    HANDLE hWL = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        // Use static_cast instead of reinterpret_cast since we know the exact type
        auto* pr = static_cast<WLParams*>(p);
        srand((unsigned)GetTickCount());
        while (true) {
            Sleep(5000 + rand() % 2000);
            try {
                // Periodically re-whitelist and update cache
                BatchWhitelistRegion(pr->h, pr->insert, pr->map, pr->base, pr->size);

                if (pr->cache) {
                    PatchCFGCache(pr->h, pr->cache, pr->base, pr->size);
                }
            }
            catch (const std::exception& e) {
                printf("[!] Whitelist guardian exception: %s\n", e.what());

                // Fallback to traditional methods
                nbeater678_bypass::nbeater678_whitelist(pr->h, pr->base, pr->size);
                if (pr->cache) {
                    nbeater678_bypass::nbeater678_cache(pr->h, pr->base, pr->size);
                }
            }
        }
        return 0;
        }, wl, 0, nullptr);
    if (hWL) CloseHandle(hWL);

    // NEW: Make memory executable AFTER whitelisting with optimized approach
    printf("[*] Step 3: Making memory executable...\n");
    {
        // First, set executable for critical sections only (.text, import thunks)
        bool execSuccess = false;
        for (auto sec : execSecs) {
            uintptr_t secBase = TargetBase + sec->VirtualAddress;
            size_t secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            printf("[*] Setting RWX section: %.*s at %p (0x%zx bytes)\n", 8, sec->Name, (void*)secBase, secSize);
            execSuccess |= SetDirectExecutable(proc._handle, secBase, secSize);
        }

        if (!execSuccess) {
            // Fallback to monolithic approach - set entire image executable
            printf("[*] Fallback: Setting entire image executable...\n");
            SetDirectExecutable(proc._handle, TargetBase, OptHeader->SizeOfImage);
        }

        // Proceed even if protection fails - guardian threads will fix later
        printf("[*] Moving to Step 4...\n");
    }

    // Gather required function pointers from imported DLLs
    void* _GetProcAddress = kernelbase.GetAddress(oxorany("GetProcAddress"));
    void* _GetModuleHandleA = kernelbase.GetAddress(oxorany("GetModuleHandleA"));
    void* _LoadLibraryA = kernelbase.GetAddress(oxorany("LoadLibraryA"));
    void* _MessageBoxA = user32.GetAddress(oxorany("MessageBoxA"));

    // Hook NtQuerySystemInformation to finish DLL initialization
    printf("[*] Step 4: Setting up hook...\n");
    // Use explicit std::vector<void*> for the extra stack pointers
    auto extraStack = std::vector<void*>{
        (void*)(loader.Start + Offsets::set_insert),
        (void*)(loader.Start + Offsets::map),
        (void*)TargetBase,
        (void*)_GetProcAddress,
        (void*)_GetModuleHandleA,
        (void*)_LoadLibraryA,
        (void*)_MessageBoxA,
        (void*)proc._handle
    };
    auto NtHk = Injector::Hook<int32_t, uint32_t, void*, ULONG, ULONG*>(proc, "NtQuerySystemInformation", NtQuerySystemInformation, extraStack);

    // Wait for the hook to finish
    printf("[*] Step 5: Waiting for DLL initialization...\n");
    Injector::HOOK_STATUS Status = (Injector::HOOK_STATUS)-1;
    Injector::HOOK_STATUS PrevStatus = Status;
    bool Done = false;
    while (!Done) {
        Process::details::RemoteRead(proc._handle, NtHk.Status, &Status);
        if (Status != PrevStatus) {
            PrevStatus = Status;
        }
        switch (Status) {
        case Injector::HOOK_FINISHED:
            Done = true;
            break;
        }
    }

    // Initialize thread management
    printf("[*] Step 6: Setting up advanced thread management...\n");
    InitThreadManagement(proc._handle, TargetBase, OptHeader->SizeOfImage);

    // CRITICAL PROTECTION LOOP:
    // This loop runs for a short time after injection to intercept any protection changes
    // Based on what Kami said, Byfron changes RWX to RW about 5-15 seconds after whitelisting
    printf("[*] Step 7: Starting protection guard...\n");
    {
        // Get accurate image size information
        IMAGE_DOS_HEADER dosHeader = {};
        IMAGE_NT_HEADERS ntHeaders = {};
        ReadProcessMemory(proc._handle, (LPCVOID)TargetBase, &dosHeader, sizeof(dosHeader), nullptr);

        size_t imageSize = 0x1000000; // Default large size
        if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
            ReadProcessMemory(proc._handle, (LPCVOID)(TargetBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr);
            if (ntHeaders.OptionalHeader.SizeOfImage > 0) {
                imageSize = ntHeaders.OptionalHeader.SizeOfImage;
            }
        }

        // Create multiple protection strategies in separate threads

        // Thread 1: Page-by-page protection restoration with instruction cache flushing
        HANDLE hThread1 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(param);
            HANDLE hProcess = std::get<0>(*params);
            uintptr_t base = std::get<1>(*params);
            size_t size = std::get<2>(*params);

            printf("[*] Protection guardian #1 started for range: 0x%p - 0x%p\n", (void*)base, (void*)(base + size));

            // Random offset to start scanning to prevent predictable patterns
            uintptr_t scanOffset = 0;

            while (true) {
                // Scan with random starting points and increments to avoid pattern detection
                scanOffset = (scanOffset + 0x1000) % size;

                for (uintptr_t offset = scanOffset; offset < size; offset += 0x1000) {
                    uintptr_t addr = base + offset;

                    MEMORY_BASIC_INFORMATION mbi = {};
                    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                        // More aggressive check - we want PAGE_EXECUTE_READWRITE specifically
                        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) != PAGE_EXECUTE_READWRITE) {
                            // Restore execution permissions - always force RWX
                            DWORD oldProtect;
                            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

                            // Touch the memory to ensure protection changes take effect
                            uint8_t buffer[16] = {};
                            SIZE_T bytesRead = 0;
                            ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead);
                            if (bytesRead > 0) {
                                WriteProcessMemory(hProcess, mbi.BaseAddress, buffer, bytesRead, nullptr);
                            }

                            FlushInstructionCache(hProcess, mbi.BaseAddress, mbi.RegionSize);

                            printf("[!] Guardian #1: Restored RWX at %p (was 0x%X)\n", mbi.BaseAddress, oldProtect);
                        }
                    }
                }

                Sleep(10); // Check even more frequently
            }

            return 0;
            }, new std::tuple<HANDLE, uintptr_t, size_t>(proc._handle, TargetBase, imageSize), 0, nullptr);

        // Thread 2: Section-level protection with regular re-application
        HANDLE hThread2 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(param);
            HANDLE hProcess = std::get<0>(*params);
            uintptr_t base = std::get<1>(*params);
            size_t size = std::get<2>(*params);

            printf("[*] Protection guardian #2 started for range: 0x%p - 0x%p\n", (void*)base, (void*)(base + size));

            // Map of sections and their desired protections
            struct SectionInfo {
                uintptr_t address;
                size_t size;
                DWORD protection;
            };

            std::vector<SectionInfo> sections;

            // Initialize section information
            IMAGE_DOS_HEADER dosHeader = {};
            ReadProcessMemory(hProcess, (LPCVOID)base, &dosHeader, sizeof(dosHeader), nullptr);

            if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS ntHeaders = {};
                ReadProcessMemory(hProcess, (LPCVOID)(base + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr);

                // Add each executable section
                DWORD sectionOffset = base + dosHeader.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                    ntHeaders.FileHeader.SizeOfOptionalHeader;

                for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                    IMAGE_SECTION_HEADER sectionHeader = {};
                    ReadProcessMemory(hProcess, (LPCVOID)(sectionOffset + i * sizeof(IMAGE_SECTION_HEADER)),
                        &sectionHeader, sizeof(IMAGE_SECTION_HEADER), nullptr);

                    // Only protect executable sections
                    if (sectionHeader.Characteristics & (IMAGE_SCN_MEM_EXECUTE)) {
                        SectionInfo section;
                        section.address = base + sectionHeader.VirtualAddress;
                        section.size = sectionHeader.Misc.VirtualSize;
                        section.protection = PAGE_EXECUTE_READWRITE;
                        sections.push_back(section);
                    }
                }
            }

            // If no sections were found, default to full image
            if (sections.empty()) {
                SectionInfo fullImage;
                fullImage.address = base;
                fullImage.size = size;
                fullImage.protection = PAGE_EXECUTE_READWRITE;
                sections.push_back(fullImage);
            }

            // Periodic forced protection reapplication to all sections
            while (true) {
                for (const auto& section : sections) {
                    DWORD oldProtect;
                    BOOL result = VirtualProtectEx(hProcess, (LPVOID)section.address,
                        section.size, section.protection, &oldProtect);

                    if (result && oldProtect != section.protection) {
                        printf("[!] Guardian #2: Restored section at %p (size: 0x%zx)\n",
                            (void*)section.address, section.size);

                        // Touch memory to enforce execution capabilities
                        for (size_t offset = 0; offset < section.size; offset += 0x1000) {
                            uint8_t byte;
                            if (ReadProcessMemory(hProcess, (LPCVOID)(section.address + offset),
                                &byte, 1, nullptr)) {
                                WriteProcessMemory(hProcess, (LPVOID)(section.address + offset),
                                    &byte, 1, nullptr);
                            }
                        }

                        // Ensure changes take effect
                        FlushInstructionCache(hProcess, (LPVOID)section.address, section.size);
                    }
                }

                Sleep(15); // Faster checking for more aggressive protection
            }

            return 0;
            }, new std::tuple<HANDLE, uintptr_t, size_t>(proc._handle, TargetBase, imageSize), 0, nullptr);

        // Thread 3: CFG Cache Refresher - continually refreshes CFG caches
        HANDLE hThread3 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(param);
            HANDLE hProcess = std::get<0>(*params);
            uintptr_t base = std::get<1>(*params);
            size_t size = std::get<2>(*params);

            printf("[*] Protection guardian #3 (CFG Cache) started for range: %p - %p\n", (void*)base, (void*)(base + size));

            // Get module for Roblox
            HMODULE robloxModule = GetRemoteModuleHandle(hProcess, L"RobloxPlayerBeta.dll");
            if (!robloxModule) {
                printf("[!] Guardian #3: Failed to get Roblox module handle\n");
                return 1;
            }

            // Get CFG cache base
            uintptr_t cfg_cache_base = 0;
            if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)robloxModule + Offsets::cfg_cachee),
                &cfg_cache_base, sizeof(cfg_cache_base), nullptr) || !cfg_cache_base) {
                printf("[!] Guardian #3: Failed to read CFG cache base\n");
                return 1;
            }

            printf("[*] Guardian #3: CFG cache base at 0x%p\n", (void*)cfg_cache_base);

            // Keep track of updated pages to reduce unnecessary updates
            std::vector<uintptr_t> updatedPages;

            while (true) {
                // Clear the update tracker periodically
                if (updatedPages.size() > 1000) {
                    updatedPages.clear();
                }

                // Get accurate memory layout
                MEMORY_BASIC_INFORMATION mbi = {};
                for (uintptr_t addr = base; addr < base + size; addr += mbi.RegionSize) {
                    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                        // Skip non-committed or pageguard memory
                        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) {
                            continue;
                        }

                        // First check if already has RWX protection
                        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                            // Already has RWX, continue with CFG cache updates
                        }
                        // Otherwise, if it has any execute protection, upgrade to RWX
                        else if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY))) {
                            // Upgrade to RWX
                            DWORD oldProtect;
                            if (VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                                printf("[!] Guardian #3: Upgraded protection from 0x%X to RWX at %p\n",
                                    oldProtect, mbi.BaseAddress);
                            }
                        }

                        // Apply CFG cache updates per page
                        for (uintptr_t page = (uintptr_t)mbi.BaseAddress;
                            page < (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                            page += 0x1000) {

                            // Skip already updated pages
                            bool alreadyUpdated = false;
                            for (const auto& updatedPage : updatedPages) {
                                if (updatedPage == page) {
                                    alreadyUpdated = true;
                                    break;
                                }
                            }

                            if (!alreadyUpdated) {
                                // Update CFG cache entries
                                uintptr_t page_aligned = page & ~Offsets::kPageMask;
                                uintptr_t entry = cfg_cache_base + (page_aligned >> 0x13);
                                uint32_t bit = 1 << (((page_aligned >> 0x10) & 7) % 32);

                                uint32_t current = 0;
                                if (ReadProcessMemory(hProcess, (LPCVOID)entry, &current, sizeof(current), nullptr)) {
                                    // Set the bit if not already set
                                    if ((current & bit) == 0) {
                                        uint32_t newValue = current | bit;
                                        if (WriteProcessMemory(hProcess, (LPVOID)entry, &newValue, sizeof(newValue), nullptr)) {
                                            printf("[!] Guardian #3: Updated CFG cache for page 0x%p (entry: 0x%p, bit: %u)\n",
                                                (void*)page_aligned, (void*)entry, bit);

                                            // Track the updated page
                                            updatedPages.push_back(page);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Also ensure the whitelist stays updated
                for (uintptr_t page = base & ~0xFFF; page < (base + size + 0xFFF) & ~0xFFF; page += 0x1000) {
                    uint64_t hash = ((page >> Offsets::kPageShift) ^ Offsets::kPageHash);
                    uintptr_t fnAddr = (uintptr_t)robloxModule + Offsets::set_insert;
                    uintptr_t mapAddr = (uintptr_t)robloxModule + Offsets::map;

                    // Only update periodically to avoid detection
                    if (rand() % 10 == 0) {
                        SyscallRemoteCall(hProcess, fnAddr, mapAddr, 0xf40ce68d, hash);
                    }
                }

                Sleep(50); // Appropriate delay between cache updates
            }

            return 0;
            }, new std::tuple<HANDLE, uintptr_t, size_t>(proc._handle, TargetBase, imageSize), 0, nullptr);

        // Thread 4: Thread protector - prevents thread termination & integrates with thread management
        HANDLE hThread4 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(param);
            HANDLE hProcess = std::get<0>(*params);
            uintptr_t base = std::get<1>(*params);
            size_t size = std::get<2>(*params);

            printf("[*] Protection guardian #4 (Thread monitor) started\n");

            int threadMgmtCounter = 0;

            while (true) {
                // Get list of threads in the target process
                HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(hProcess));
                if (hThreadSnap != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te32;
                    te32.dwSize = sizeof(THREADENTRY32);

                    if (Thread32First(hThreadSnap, &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == GetProcessId(hProcess)) {
                                // This is a thread in our target process
                                // Check if it's executing within our DLL's memory range
                                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                                if (hThread) {
                                    CONTEXT ctx = { 0 };
                                    ctx.ContextFlags = CONTEXT_CONTROL;

                                    if (GetThreadContext(hThread, &ctx)) {
                                        if (ctx.Rip >= base && ctx.Rip < base + size) {
                                            // This thread is executing our DLL code - protect it

                                            // Store thread ID for protection
                                            EnterCriticalSection(&g_ProtectionCS);
                                            g_ProtectedThreads.push_back(te32.th32ThreadID);
                                            LeaveCriticalSection(&g_ProtectionCS);

                                            // Check thread suspend count and resume if suspended
                                            DWORD suspendCount = SuspendThread(hThread);
                                            if (suspendCount > 0) {
                                                printf("[!] Guardian #4: Found suspended thread executing our code, resuming (id: %u)\n",
                                                    te32.th32ThreadID);

                                                // Resume the thread immediately
                                                while (suspendCount > 0) {
                                                    ResumeThread(hThread);
                                                    suspendCount--;
                                                }

                                                // Extra resume to be safe
                                                ResumeThread(hThread);
                                            }
                                            else {
                                                // Thread not suspended, resume our query
                                                ResumeThread(hThread);
                                            }
                                        }
                                    }
                                    CloseHandle(hThread);
                                }
                            }
                        } while (Thread32Next(hThreadSnap, &te32));
                    }
                    CloseHandle(hThreadSnap);
                }

                // Integrate with ThreadManager
                threadMgmtCounter++;
                if (threadMgmtCounter >= 20) {
                    threadMgmtCounter = 0;

                    // Check if we need to revive threads via thread manager
                    if (g_ThreadManager) {
                        // Check total active threads in DLL
                        std::vector<DWORD> threadsInDll = g_ThreadManager->FindThreadsInDll();

                        if (threadsInDll.size() < 2) {
                            // Not enough threads running in our DLL, create more
                            if (g_ThreadManager->ReviveThreads(true)) {
                                printf("[+] Guardian #4: Created new hidden threads to maintain execution\n");
                            }

                            // Also try to restore thread contexts that might have been manipulated
                            g_ThreadManager->RestoreThreadContexts();
                        }

                        // Periodically camouflage threads to avoid detection patterns
                        if (rand() % 5 == 0) {
                            g_ThreadManager->CamouflageThreads();
                        }
                    }
                }

                Sleep(10); // Check very frequently
            }

            return 0;
            }, new std::tuple<HANDLE, uintptr_t, size_t>(proc._handle, TargetBase, imageSize), 0, nullptr);

        // Prepare slots for additional guardians
        HANDLE hThread5 = NULL;
        HANDLE hThread7 = NULL;

        // Guardian 5: Entry-point integrity monitor
        {
            // Capture the remote entry-point and its original bytes
            uintptr_t entryPoint = TargetBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
            const size_t entrySize = 64;
            uint8_t* origEntry = new uint8_t[entrySize];
            ReadProcessMemory(proc._handle, reinterpret_cast<LPCVOID>(entryPoint), origEntry, entrySize, nullptr);

            struct EntryGuardianParams { HANDLE hProcess; uintptr_t entry; uint8_t* orig; size_t size; };
            auto* epParams = new EntryGuardianParams{ proc._handle, entryPoint, origEntry, entrySize };

            hThread5 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                auto* p = reinterpret_cast<EntryGuardianParams*>(param);
                printf("[*] Guardian #5: Entry-point integrity monitor started at %p\n", (void*)p->entry);
                std::vector<uint8_t> buffer(p->size);
                while (true) {
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(p->hProcess, reinterpret_cast<LPCVOID>(p->entry), buffer.data(), p->size, &bytesRead)
                        && bytesRead == p->size
                        && memcmp(buffer.data(), p->orig, p->size) != 0) {
                        DWORD oldProtect;
                        VirtualProtectEx(p->hProcess, reinterpret_cast<LPVOID>(p->entry), p->size, PAGE_EXECUTE_READWRITE, &oldProtect);
                        WriteProcessMemory(p->hProcess, reinterpret_cast<LPVOID>(p->entry), p->orig, p->size, nullptr);
                        FlushInstructionCache(p->hProcess, reinterpret_cast<LPCVOID>(p->entry), p->size);
                        printf("[!] Guardian #5: Restored entry-point at %p\n", (void*)p->entry);
                    }
                    Sleep(500);
                }
                return 0;
                }, epParams, 0, nullptr);

        }

        // Guardian 7: NTDLL prologue monitor for NtProtectVirtualMemory
        {
            HMODULE hLocalNtdll = GetModuleHandleA("ntdll.dll");
            uintptr_t localBase = reinterpret_cast<uintptr_t>(hLocalNtdll);
            void* fnLocal = GetProcAddress(hLocalNtdll, "NtProtectVirtualMemory");
            const size_t hookSize = 16;
            uint8_t* origBytes = new uint8_t[hookSize];
            memcpy(origBytes, fnLocal, hookSize);
            uintptr_t remoteBase = reinterpret_cast<uintptr_t>(GetRemoteModuleHandle(proc._handle, L"ntdll.dll"));
            uintptr_t fnRemote = remoteBase + (reinterpret_cast<uintptr_t>(fnLocal) - localBase);

            struct HookMonitorParams { HANDLE hProcess; uintptr_t fnRemote; uint8_t* orig; size_t size; };
            auto* hm = new HookMonitorParams{ proc._handle, fnRemote, origBytes, hookSize };

            hThread7 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                auto* p = reinterpret_cast<HookMonitorParams*>(param);
                printf("[*] Guardian #7: NTDLL hook monitor started for %p\n", (void*)p->fnRemote);
                uint8_t buffer[hookSize];
                while (true) {
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(p->hProcess, reinterpret_cast<LPCVOID>(p->fnRemote), buffer, p->size, &bytesRead)
                        && bytesRead == p->size
                        && memcmp(buffer, p->orig, p->size) != 0) {
                        DWORD oldProtect;
                        VirtualProtectEx(p->hProcess, reinterpret_cast<LPVOID>(p->fnRemote), p->size, PAGE_EXECUTE_READWRITE, &oldProtect);
                        WriteProcessMemory(p->hProcess, reinterpret_cast<LPVOID>(p->fnRemote), p->orig, p->size, nullptr);
                        FlushInstructionCache(p->hProcess, reinterpret_cast<LPCVOID>(p->fnRemote), p->size);
                        printf("[!] Guardian #7: Restored NTDLL prologue at %p\n", (void*)p->fnRemote);
                    }
                    Sleep(500);
                }
                return 0;
                }, hm, 0, nullptr);

        }

        // Guardian 8: IAT watchdog
        struct IATGuardianParams { HANDLE hProcess; uintptr_t base; };
        auto* p8 = new IATGuardianParams{ proc._handle, TargetBase };
        HANDLE hThread8 = CreateThread(nullptr, 0, [](LPVOID lp) -> DWORD {
            auto* p = reinterpret_cast<IATGuardianParams*>(lp);
            HANDLE hProcess = p->hProcess;
            uintptr_t base = p->base;
            IMAGE_DOS_HEADER dos = {};
            IMAGE_NT_HEADERS nt = {};
            ReadProcessMemory(hProcess, (LPCVOID)base, &dos, sizeof(dos), nullptr);
            ReadProcessMemory(hProcess, (LPCVOID)(base + dos.e_lfanew), &nt, sizeof(nt), nullptr);
            auto importDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDir.VirtualAddress && importDir.Size) {
                uintptr_t descAddr = base + importDir.VirtualAddress;
                IMAGE_IMPORT_DESCRIPTOR importDesc = {};
                while (true) {
                    ReadProcessMemory(hProcess, (LPCVOID)descAddr, &importDesc, sizeof(importDesc), nullptr);
                    if (!importDesc.Name) break;
                    char modName[MAX_PATH] = {};
                    ReadProcessMemory(hProcess, (LPCVOID)(base + importDesc.Name), modName, sizeof(modName), nullptr);
                    HMODULE localMod = GetModuleHandleA(modName);
                    if (localMod) {
                        uintptr_t thunkRef = base + importDesc.OriginalFirstThunk;
                        uintptr_t funcRef = base + importDesc.FirstThunk;
                        while (true) {
                            uintptr_t thunkData = 0;
                            ReadProcessMemory(hProcess, (LPCVOID)thunkRef, &thunkData, sizeof(thunkData), nullptr);
                            if (!thunkData) break;
                            uintptr_t target = 0;
                            if (IMAGE_SNAP_BY_ORDINAL(thunkData)) {
                                WORD ord = static_cast<WORD>(thunkData & 0xFFFF);
                                target = reinterpret_cast<uintptr_t>(GetProcAddress(localMod, MAKEINTRESOURCEA(ord)));
                            }
                            else {
                                IMAGE_IMPORT_BY_NAME ibn = {};
                                ReadProcessMemory(hProcess, (LPCVOID)(base + thunkData), &ibn, sizeof(ibn), nullptr);
                                char fname[256] = {};
                                ReadProcessMemory(hProcess, (LPCVOID)(base + thunkData + offsetof(IMAGE_IMPORT_BY_NAME, Name)), fname, sizeof(fname), nullptr);
                                target = reinterpret_cast<uintptr_t>(GetProcAddress(localMod, fname));
                            }
                            uintptr_t current = 0;
                            ReadProcessMemory(hProcess, (LPCVOID)funcRef, &current, sizeof(current), nullptr);
                            if (current != target) {
                                DWORD oldProt;
                                VirtualProtectEx(hProcess, (LPVOID)funcRef, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProt);
                                WriteProcessMemory(hProcess, (LPVOID)funcRef, &target, sizeof(target), nullptr);
                                VirtualProtectEx(hProcess, (LPVOID)funcRef, sizeof(uintptr_t), oldProt, &oldProt);
                                FlushInstructionCache(hProcess, (LPCVOID)funcRef, sizeof(uintptr_t));
                            }
                            thunkRef += sizeof(uintptr_t);
                            funcRef += sizeof(uintptr_t);
                        }
                    }
                    descAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                }
            }
            Sleep(1000);
            return 0;
            }, p8, 0, nullptr);

        // Guardian 9: PEB module-list monitor (stealth)
        struct PEBGuardianParams { HANDLE hProcess; uintptr_t base; };
        auto* p9 = new PEBGuardianParams{ proc._handle, TargetBase };
        HANDLE hThread9 = CreateThread(nullptr, 0, [](LPVOID lp) -> DWORD {
            auto* p = reinterpret_cast<PEBGuardianParams*>(lp);
            HANDLE hProcess = p->hProcess;
            uintptr_t base = p->base;
            // resolve NtQueryInformationProcess dynamically
            auto fnQIP = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess")
                );
            if (!fnQIP) return 1;
            while (true) {
                bool found = false;
                PROCESS_BASIC_INFORMATION pbi;
                ULONG retLen = 0;
                if (NT_SUCCESS(fnQIP(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen))) {
                    PBYTE pebAddr = reinterpret_cast<PBYTE>(pbi.PebBaseAddress);
                    // read Ldr pointer from PEB (offset 0x18)
                    PVOID ldrAddr = nullptr;
                    ReadProcessMemory(hProcess, pebAddr + 0x18, &ldrAddr, sizeof(ldrAddr), nullptr);
                    if (ldrAddr) {
                        // read InLoadOrderModuleList head (offset 0x10)
                        PVOID head = nullptr;
                        ReadProcessMemory(hProcess, reinterpret_cast<PBYTE>(ldrAddr) + 0x10, &head, sizeof(head), nullptr);
                        PVOID curr = head;
                        do {
                            // read DllBase at offset 0x30 in LDR_DATA_TABLE_ENTRY
                            PVOID dllBase = nullptr;
                            ReadProcessMemory(hProcess, reinterpret_cast<PBYTE>(curr) + 0x30, &dllBase, sizeof(dllBase), nullptr);
                            if (reinterpret_cast<uintptr_t>(dllBase) == base) { found = true; break; }
                            // next link (Flink at start of LIST_ENTRY)
                            ReadProcessMemory(hProcess, curr, &curr, sizeof(curr), nullptr);
                        } while (curr && curr != head);
                    }
                }
                if (!found) {
                    printf("[!] Guardian #9: DLL missing from PEB module list\n");
                }
                Sleep(2000 + rand() % 500);
            }
            return 0;
            }, p9, 0, nullptr);

        // Detach the threads so they continue running independently
        if (hThread1) CloseHandle(hThread1);
        if (hThread2) CloseHandle(hThread2);
        if (hThread3) CloseHandle(hThread3);
        if (hThread4) CloseHandle(hThread4);
        if (hThread5) CloseHandle(hThread5);
        if (hThread7) CloseHandle(hThread7);
        if (hThread8) CloseHandle(hThread8);
        if (hThread9) CloseHandle(hThread9);

        // Guardian 11: API prologue monitor
        struct APIPrologueParams { HANDLE hProcess; uintptr_t localBase; uintptr_t remoteBase; };
        auto* p11 = new APIPrologueParams{
            proc._handle,
            reinterpret_cast<uintptr_t>(GetModuleHandleA("ntdll.dll")),
            reinterpret_cast<uintptr_t>(GetRemoteModuleHandle(proc._handle, L"ntdll.dll"))
        };
        HANDLE hThread11 = CreateThread(nullptr, 0, [](LPVOID lp) -> DWORD {
            auto* p = reinterpret_cast<APIPrologueParams*>(lp);
            HANDLE hProcess = p->hProcess;
            uintptr_t localBase = p->localBase;
            uintptr_t remoteBase = p->remoteBase;
            const char* names[] = {
                "NtProtectVirtualMemory",
        "NtQuerySystemInformation",
                "NtSuspendThread",
                "NtResumeThread"
            };
            size_t count = sizeof(names) / sizeof(names[0]);
            const size_t hookSize = 16;
            // capture original prologues
            HMODULE hLocal = reinterpret_cast<HMODULE>(localBase);
            std::vector<std::vector<BYTE>> orig(count, std::vector<BYTE>(hookSize));
            for (size_t i = 0; i < count; i++) {
                void* fn = GetProcAddress(hLocal, names[i]);
                memcpy(orig[i].data(), fn, hookSize);
            }
            while (true) {
                for (size_t i = 0; i < count; i++) {
                    void* fnLocal = GetProcAddress(hLocal, names[i]);
                    uintptr_t offset = reinterpret_cast<uintptr_t>(fnLocal) - localBase;
                    uintptr_t fnRemote = remoteBase + offset;
                    BYTE curr[hookSize]; SIZE_T bytesRead = 0;
                    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(fnRemote), curr, hookSize, &bytesRead);
                    if (bytesRead == hookSize && memcmp(curr, orig[i].data(), hookSize) != 0) {
                        DWORD oldProt;
                        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(fnRemote), hookSize, PAGE_EXECUTE_READWRITE, &oldProt);
                        WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(fnRemote), orig[i].data(), hookSize, nullptr);
                        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(fnRemote), hookSize, oldProt, &oldProt);
                        FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(fnRemote), hookSize);
                        printf("[!] Guardian #11: Restored %s prologue at %p\n", names[i], (void*)fnRemote);
                    }
                }
                Sleep(1000);
            }
            return 0;
            }, p11, 0, nullptr);
        if (hThread11) CloseHandle(hThread11);

        // Guardian 13: TLS callback integrity monitor
        struct TLSGuardianParams { HANDLE hProcess; uintptr_t base; };
        auto* p13 = new TLSGuardianParams{ proc._handle, TargetBase };
        HANDLE hThread13 = CreateThread(nullptr, 0, [](LPVOID lp) -> DWORD {
            auto* p = reinterpret_cast<TLSGuardianParams*>(lp);
            HANDLE hProcess = p->hProcess;
            uintptr_t base = p->base;
            // read TLS directory
            IMAGE_DOS_HEADER dos = {};
            IMAGE_NT_HEADERS nt = {};
            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), nullptr);
            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(base + dos.e_lfanew), &nt, sizeof(nt), nullptr);
            auto tlsDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (!tlsDir.VirtualAddress || !tlsDir.Size) return 0;
            IMAGE_TLS_DIRECTORY tlsData = {};
            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(base + tlsDir.VirtualAddress), &tlsData, sizeof(tlsData), nullptr);
            // AddressOfCallBacks is ULONGLONG on x64, convert via static_cast
            uintptr_t cbArray = static_cast<uintptr_t>(tlsData.AddressOfCallBacks);
            // gather callback addresses
            std::vector<uintptr_t> cbs;
            for (size_t i = 0;; i++) {
                uintptr_t cb = 0;
                ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cbArray + i * sizeof(uintptr_t)), &cb, sizeof(cb), nullptr);
                if (!cb) break;
                cbs.push_back(cb);
            }
            const size_t hookSize = 16;
            // capture original bytes
            std::vector<std::vector<BYTE>> orig(cbs.size(), std::vector<BYTE>(hookSize));
            for (size_t i = 0; i < cbs.size(); i++) {
                ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cbs[i]), orig[i].data(), hookSize, nullptr);
            }
            while (true) {
                for (size_t i = 0; i < cbs.size(); i++) {
                    BYTE curr[hookSize]; SIZE_T bytesRead = 0;
                    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(cbs[i]), curr, hookSize, &bytesRead);
                    if (bytesRead == hookSize && memcmp(curr, orig[i].data(), hookSize) != 0) {
                        DWORD oldProt;
                        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(cbs[i]), hookSize, PAGE_EXECUTE_READWRITE, &oldProt);
                        WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(cbs[i]), orig[i].data(), hookSize, nullptr);
                        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(cbs[i]), hookSize, oldProt, &oldProt);
                        FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(cbs[i]), hookSize);
                        printf("[!] Guardian #13: Restored TLS callback at %p\n", (void*)cbs[i]);
                    }
                }
                Sleep(2000);
            }
            return 0;
            }, p13, 0, nullptr);
        if (hThread13) CloseHandle(hThread13);

        // Guardian 6: RWX enforce - repeatedly apply PAGE_EXECUTE_READWRITE
        HANDLE hThread6 = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto params = reinterpret_cast<std::tuple<HANDLE, uintptr_t, size_t>*>(param);
            HANDLE hProcess = std::get<0>(*params);
            uintptr_t base = std::get<1>(*params);
            size_t size = std::get<2>(*params);
            printf("[*] Protection guardian #6 (RWX enforce) started for range: %p - %p\n", (void*)base, (void*)(base + size));

            // Add active thread management integration
            DWORD lastThreadRevival = GetTickCount();

            while (true) {
                // Apply RWX directly but check more frequently
                SetDirectExecutable(hProcess, base, size);

                // Force thread revival more frequently to ensure execution
                DWORD currentTime = GetTickCount();
                if (currentTime - lastThreadRevival > 1000) { // Every second
                    lastThreadRevival = currentTime;
                    if (g_ThreadManager) {
                        // Force create new threads periodically
                        if (g_ThreadManager->ReviveThreads(true)) {
                            printf("[+] Guardian #6: Created new hidden threads to maintain execution\n");
                        }
                    }
                }

                // Sleep less to be more responsive
                Sleep(250);
            }
            return 0;
            }, new std::tuple<HANDLE, uintptr_t, size_t>(proc._handle, TargetBase, imageSize), 0, nullptr);
        if (hThread6) CloseHandle(hThread6);
    }

    printf("[*] Step 8: Unhooking and finishing up...\n");
    Injector::Unhook<int32_t, uint32_t, void*, ULONG, ULONG*>(NtHk);
    printf("[*] Injection completed successfully!\n");
    return true;
}

int main()
{
    try {
        // Set Windows error mode to prevent system error dialogs
        UINT oldErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

        printf("[*] Starting Roblox executor - initializing...\n");

        // Wait for Roblox process
        Process::Object proc;

        try {
            proc = Process::WaitForProcess(oxorany(L"RobloxPlayerBeta.exe"));
            printf("[+] Connected to Roblox process (PID: %u)\n", proc._id);
        }
        catch (const std::exception& e) {
            printf("[!] Error connecting to Roblox: %s\n", e.what());
            printf("[!] Make sure Roblox is running and try again\n");
            Sleep(3000);
            return 1;
        }

        std::string dllname = oxorany("Base.dll");
        printf((oxorany("Inject ") + dllname + oxorany("\n")).c_str());

        // Store the target base address for monitoring
        uintptr_t injectedBase = 0;
        bool injectionSuccess = false;

        try {
            injectionSuccess = ManualMap(proc, dllname);
        }
        catch (const std::exception& e) {
            printf("[!] Error during injection: %s\n", e.what());
            printf("[!] Will retry on next launch\n");
            Sleep(3000);
            return 1;
        }

        if (injectionSuccess) {
            printf((dllname + oxorany(" Was successfully Injected! Monitoring for stability...\n")).c_str());

            // Find our injected DLL in the target process - with error handling
            MODULEENTRY32W me32{};
            me32.dwSize = sizeof(MODULEENTRY32W);
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proc._id);

            if (hSnap != INVALID_HANDLE_VALUE) {
                if (Module32FirstW(hSnap, &me32)) {
                    do {
                        // Based on size estimation, find our recently injected module
                        // This is approximate but should work for our needs
                        std::wstring modName = me32.szModule;
                        if (me32.modBaseSize < 5000000 && me32.modBaseSize > 10000) {
                            // This is likely our injected DLL
                            injectedBase = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                            printf("[+] Located potential injected module at: 0x%p (size: %u)\n",
                                me32.modBaseAddr, me32.modBaseSize);
                        }
                    } while (Module32NextW(hSnap, &me32));
                }
                CloseHandle(hSnap);
            }

            // If we couldn't find the injected module base, use a fallback
            if (injectedBase == 0) {
                printf("[!] Warning: Could not locate injected module, using fallback detection\n");

                // Try to look for recently allocated RWX memory in the target process
                MEMORY_BASIC_INFORMATION mbi = {};
                for (uintptr_t addr = 0; addr < 0x70000000000; addr += mbi.RegionSize ? mbi.RegionSize : 0x1000) {
                    if (VirtualQueryEx(proc._handle, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
                        if (mbi.State == MEM_COMMIT &&
                            mbi.Type == MEM_PRIVATE &&
                            mbi.Protect == PAGE_EXECUTE_READWRITE &&
                            mbi.RegionSize > 10000 && mbi.RegionSize < 5000000) {
                            // This could be our module
                            injectedBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                            printf("[+] Found potential RWX memory at 0x%p (size: %zu bytes)\n",
                                mbi.BaseAddress, mbi.RegionSize);
                            break;
                        }
                    }
                }
            }

            // Final fallback if we still don't have a base address
            if (injectedBase == 0) {
                printf("[!] Could not locate injected module base. Will continue but monitoring may be less effective.\n");
                Sleep(1000);
            }

            // Create master monitoring thread that periodically checks all protections
            HANDLE monitorThread = CreateThread(nullptr, 0,
                [](LPVOID param) -> DWORD {
                    auto params = reinterpret_cast<std::pair<HANDLE, uintptr_t>*>(param);
                    HANDLE hProcess = params->first;
                    uintptr_t base = params->second;

                    // Keep statistics about protection violations found
                    size_t totalViolations = 0;
                    size_t consecutiveSuccesses = 0;
                    DWORD lastViolationTime = GetTickCount();
                    DWORD lastHeartbeat = GetTickCount();

                    printf("[*] Master monitor thread started for injected module at 0x%p\n", (void*)base);
                    fflush(stdout); // Ensure output is displayed immediately

                    // Get Roblox module for CFG operations
                    HMODULE robloxModule = GetRemoteModuleHandle(hProcess, L"RobloxPlayerBeta.dll");
                    if (!robloxModule) {
                        printf("[!] Monitor: Failed to get Roblox module handle\n");
                        fflush(stdout);
                    }

                    // Get CFG cache base for direct updates
                    uintptr_t cfg_cache_base = 0;
                    if (robloxModule) {
                        ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>((uintptr_t)robloxModule + Offsets::cfg_cachee),
                            &cfg_cache_base, sizeof(cfg_cache_base), nullptr);
                        if (cfg_cache_base) {
                            printf("[*] Monitor: Found CFG cache at 0x%p\n", (void*)cfg_cache_base);
                            fflush(stdout);
                        }
                    }

                    // Create a dedicated console management thread with enhanced protection
                    HANDLE consoleThread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                        // Make this thread harder to detect and terminate
                        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

                        // Try to hide from debugger
                        typedef NTSTATUS(NTAPI* pNtSetInformationThreadFn)(
                            HANDLE ThreadHandle,
                            ULONG ThreadInformationClass,
                            PVOID ThreadInformation,
                            ULONG ThreadInformationLength
                            );

                        // Load NtSetInformationThread dynamically
                        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                        if (ntdll) {
                            pNtSetInformationThreadFn NtSetThreadFn = (pNtSetInformationThreadFn)
                                GetProcAddress(ntdll, "NtSetInformationThread");

                            if (NtSetThreadFn) {
                                // Use ThreadHideFromDebugger (0x11)
                                NtSetThreadFn(GetCurrentThread(), 0x11, NULL, 0);

                                // Optionally mark thread as critical (system will crash if thread is terminated)
                                // USE WITH EXTREME CAUTION - Uncomment if you absolutely need this thread to survive
                                /*
                                ULONG breakOnTermination = 1;
                                NtSetThreadFn(GetCurrentThread(), 0x1E, &breakOnTermination, sizeof(breakOnTermination));
                                */

                                // Try to spoof the thread start address to avoid detection
                                PVOID kernelBase = GetModuleHandleA("kernel32.dll");
                                if (kernelBase) {
                                    // Use a legitimate Windows API as fake entry point
                                    PVOID fakeStartAddr = GetProcAddress((HMODULE)kernelBase, "WriteConsoleW");
                                    if (fakeStartAddr) {
                                        // ThreadQuerySetWin32StartAddress = 9
                                        NtSetThreadFn(GetCurrentThread(), 9, &fakeStartAddr, sizeof(fakeStartAddr));
                                    }
                                }
                            }
                        }

                        // Continuously ensure console output works with redundancy pattern
                        // Store multiple file handles as backup
                        std::vector<FILE*> outputStreams;
                        outputStreams.push_back(stdout);

                        // Try to open additional console output streams
                        FILE* auxStream = freopen("CONOUT$", "w", stdout);
                        if (auxStream && auxStream != stdout) {
                            outputStreams.push_back(auxStream);
                        }

                        // Main console monitoring loop with multiple resilience methods
                        DWORD heartbeatInterval = 2000;  // Start at 2 seconds
                        DWORD lastHeartbeat = GetTickCount();
                        DWORD startTime = GetTickCount();

                        while (true) {
                            DWORD currentTime = GetTickCount();

                            // Dynamic heartbeat timing
                            if (currentTime - lastHeartbeat > heartbeatInterval) {
                                // Print using multiple methods for redundancy
                                printf("[*] Console alive: T+%u ms (ID:%u)\n",
                                    currentTime - startTime, GetCurrentThreadId());

                                // Directly use Windows API as fallback for console output
                                char buffer[128];
                                sprintf_s(buffer, "[*] Direct console write: T+%u ms\n", currentTime - startTime);
                                DWORD written = 0;
                                WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, (DWORD)strlen(buffer), &written, NULL);

                                // Flush all output streams
                                for (FILE* stream : outputStreams) {
                                    if (stream) fflush(stream);
                                }

                                lastHeartbeat = currentTime;

                                // Adjust heartbeat interval based on uptime for better stealth
                                // After a while, reduce frequency to avoid detection
                                if (currentTime - startTime > 60000) {  // After 1 minute
                                    heartbeatInterval = 5000;  // 5 seconds
                                }
                                if (currentTime - startTime > 300000) { // After 5 minutes
                                    heartbeatInterval = 10000; // 10 seconds
                                }
                            }

                            // Check if stdout has errors and try to reopen if needed
                            if (ferror(stdout)) {
                                clearerr(stdout);
                                // Create a new stdout handle
                                FILE* newStdout = freopen("CONOUT$", "w", stdout);
                                if (newStdout) {
                                    printf("[!] Recovered stdout after error\n");
                                    fflush(stdout);

                                    // Add to our output streams if unique
                                    bool found = false;
                                    for (FILE* stream : outputStreams) {
                                        if (stream == newStdout) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found) outputStreams.push_back(newStdout);
                                }
                            }

                            // Sleep briefly but wake up frequently to check status
                            for (int i = 0; i < 10; i++) {
                                Sleep(20);  // Short sleeps to be more responsive
                            }
                        }

                        return 0;
                        }, nullptr, 0, nullptr);

                    if (consoleThread) {
                        printf("[+] Started dedicated console monitoring thread with enhanced protection\n");
                        fflush(stdout);

                        // Set high priority for the console thread
                        SetThreadPriority(consoleThread, THREAD_PRIORITY_TIME_CRITICAL);

                        // Don't close the handle to keep the thread reference count higher
                        // This makes it harder for the system to clean up the thread if it terminates
                        // CloseHandle(consoleThread);
                    }

                    // Main monitor loop would normally go here
                    // For now, we'll just do periodic heartbeats to verify printing works
                    while (true) {
                        DWORD currentTime = GetTickCount();

                        // Perform heartbeat every 2 seconds
                        if (currentTime - lastHeartbeat > 2000) {
                            printf("[*] Monitor heartbeat at %u ms\n", currentTime);
                            fflush(stdout);
                            lastHeartbeat = currentTime;
                        }

                        // Sleep briefly to avoid consuming too much CPU
                        Sleep(200);
                    }

                    delete params;
                    return 0;
                },
                new std::pair<HANDLE, uintptr_t>(proc._handle, injectedBase), 0, nullptr);

            if (monitorThread) {
                // Don't close the monitor thread - let it run
                // CloseHandle(monitorThread);
                printf("[+] Master monitor thread started and running\n");
                fflush(stdout);
            }

            // Block until the target process exits
            printf("Monitoring target process. Waiting for it to exit...\n");
            fflush(stdout); // Ensure this message is displayed
            WaitForSingleObject(proc._handle, INFINITE);

            // Clean up thread management before exiting
            CleanupThreadManagement();
        }
        else {
            printf((oxorany("Failed to inject ") + dllname).c_str());
        }

        return 0;
    }
    catch (const std::exception& e) {
        printf("[!] Unexpected error: %s\n", e.what());
        return 1;
    }
}
