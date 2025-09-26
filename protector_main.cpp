// protector_main.cpp
// Main entry point for the protector application.
// Features a Win32 GUI to select files, specify parameters, and initiate the protection process.
// The protection logic is run on a separate thread to keep the UI responsive.

#include <windows.h>
#include <commdlg.h>
#include <string>
#include <iostream>
#include <vector>
#include <process.h> // For _beginthreadex
#include <Richedit.h> // For the log box
#include "loader_core.h"

// --- Control IDs ---
#define IDC_DLL_EDIT 101
#define IDC_DLL_BUTTON 102
#define IDC_META_EDIT 103
#define IDC_META_BUTTON 104
#define IDC_RVA_EDIT 105
#define IDC_PROTECT_BUTTON 106
#define IDC_LOG_RICHEDIT 107
#define IDM_FILE_EXIT 201
#define IDM_HELP_ABOUT 202

// --- Custom Window Messages ---
#define WM_APP_LOG_MSG (WM_APP + 1)

// --- Global Variables ---
HWND hWnd;
HWND hEditDll, hEditMetadata, hEditRva, hBtnProtect, hLog;
HINSTANCE hInst;
HFONT hFont;

// Struct to pass parameters to the worker thread
struct ThreadParams {
    std::string dll_path;
    std::string metadata_path;
    uint64_t function_rva;
};

// --- Function Prototypes ---
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void AddControls(HWND);
void CreateMainMenu(HWND);
void LogMessage(const std::string& msg);
unsigned __stdcall ProtectionThread(void* pArguments);

// --- Main Entry Point ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    // Load the rich edit library
    LoadLibraryA("Richedit20.dll");

    WNDCLASSA wc = { 0 };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "UnityProtectorClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    hWnd = CreateWindowA("UnityProtectorClass", "Unity Game Protector - 2025 Edition",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX, // Disable maximize
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 450,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}

// --- Window Procedure ---
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        CreateMainMenu(hWnd);
        AddControls(hWnd);
        break;
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDM_FILE_EXIT:
            PostQuitMessage(0);
            break;
        case IDM_HELP_ABOUT:
            MessageBoxA(hWnd, "Unity Game Protector\nVersion 1.0\n\nAn IL2CPP Obfuscator for Unity.", "About", MB_OK | MB_ICONINFORMATION);
            break;
        case IDC_DLL_BUTTON: {
            char szFile[MAX_PATH] = { 0 };
            OPENFILENAMEA ofn = { sizeof(ofn) };
            ofn.hwndOwner = hWnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = sizeof(szFile);
            ofn.lpstrFilter = "GameAssembly DLL\0GameAssembly.dll\0All DLLs\0*.dll\0";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileNameA(&ofn)) {
                SetWindowTextA(hEditDll, szFile);
            }
        }
                           break;
        case IDC_META_BUTTON: {
            char szFile[MAX_PATH] = { 0 };
            OPENFILENAMEA ofn = { sizeof(ofn) };
            ofn.hwndOwner = hWnd;
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = sizeof(szFile);
            ofn.lpstrFilter = "Metadata File\0global-metadata.dat\0All Files\0*.*\0";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileNameA(&ofn)) {
                SetWindowTextA(hEditMetadata, szFile);
            }
        }
                            break;
        case IDC_PROTECT_BUTTON: {
            char dll_buf[MAX_PATH], meta_buf[MAX_PATH], rva_buf[32];
            GetWindowTextA(hEditDll, dll_buf, MAX_PATH);
            GetWindowTextA(hEditMetadata, meta_buf, MAX_PATH);
            GetWindowTextA(hEditRva, rva_buf, 32);

            if (strlen(dll_buf) == 0 || strlen(meta_buf) == 0 || strlen(rva_buf) == 0) {
                MessageBoxA(hWnd, "Please fill in all fields before protecting.", "Input Error", MB_OK | MB_ICONWARNING);
                return 0;
            }

            uint64_t func_rva = 0;
            try {
                func_rva = std::stoull(rva_buf, nullptr, 16);
            }
            catch (...) {
                MessageBoxA(hWnd, "Invalid RVA format. Please enter a hexadecimal value (e.g., 0x123AB).", "Input Error", MB_OK | MB_ICONERROR);
                return 0;
            }

            // Use a struct to pass data to the new thread
            ThreadParams* params = new ThreadParams;
            params->dll_path = dll_buf;
            params->metadata_path = meta_buf;
            params->function_rva = func_rva;

            // Disable UI and start worker thread
            EnableWindow(hBtnProtect, FALSE);
            SetWindowTextA(hLog, ""); // Clear log
            LogMessage("Starting protection process...\n");
            _beginthreadex(NULL, 0, ProtectionThread, params, 0, NULL);
        }
                               break;
        }
    }
                   break;
                   // Custom message from worker thread to log text
    case WM_APP_LOG_MSG: {
        char* msg = (char*)lParam;
        LogMessage(msg);
        delete[] msg; // Free the allocated memory
    }
                       break;
    case WM_DESTROY:
        DeleteObject(hFont);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }
    return 0;
}

// --- UI Creation ---
void AddControls(HWND hWnd) {
    hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    auto CreateLabel = [&](const char* text, int x, int y, int w, int h) {
        HWND hStatic = CreateWindowA("STATIC", text, WS_CHILD | WS_VISIBLE, x, y, w, h, hWnd, NULL, hInst, NULL);
        SendMessage(hStatic, WM_SETFONT, (WPARAM)hFont, TRUE);
        };

    // DLL Path
    CreateLabel("Target DLL:", 10, 10, 150, 20);
    hEditDll = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 35, 450, 25, hWnd, (HMENU)IDC_DLL_EDIT, hInst, NULL);
    CreateWindowA("BUTTON", "...", WS_CHILD | WS_VISIBLE, 470, 35, 100, 25, hWnd, (HMENU)IDC_DLL_BUTTON, hInst, NULL);

    // Metadata Path
    CreateLabel("Metadata File:", 10, 70, 150, 20);
    hEditMetadata = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 95, 450, 25, hWnd, (HMENU)IDC_META_EDIT, hInst, NULL);
    CreateWindowA("BUTTON", "...", WS_CHILD | WS_VISIBLE, 470, 95, 100, 25, hWnd, (HMENU)IDC_META_BUTTON, hInst, NULL);

    // Function RVA
    CreateLabel("Function RVA (hex):", 10, 130, 150, 20);
    hEditRva = CreateWindowA("EDIT", "0x", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 155, 450, 25, hWnd, (HMENU)IDC_RVA_EDIT, hInst, NULL);

    // Protect Button
    hBtnProtect = CreateWindowA("BUTTON", "Protect Files", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 470, 155, 100, 25, hWnd, (HMENU)IDC_PROTECT_BUTTON, hInst, NULL);

    // Log Window
    CreateLabel("Log:", 10, 190, 100, 20);
    hLog = CreateWindowExA(0, RICHEDIT_CLASSA, "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        10, 215, 560, 150, hWnd, (HMENU)IDC_LOG_RICHEDIT, hInst, NULL);

    // Set font for all controls
    SendMessage(hEditDll, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hEditMetadata, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hEditRva, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hBtnProtect, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLog, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void CreateMainMenu(HWND hWnd) {
    HMENU hMenubar = CreateMenu();
    HMENU hFileMenu = CreateMenu();
    HMENU hHelpMenu = CreateMenu();

    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "Exit");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "About");

    AppendMenuA(hMenubar, MF_POPUP, (UINT_PTR)hFileMenu, "File");
    AppendMenuA(hMenubar, MF_POPUP, (UINT_PTR)hHelpMenu, "Help");

    SetMenu(hWnd, hMenubar);
}

// --- Logging and Threading ---

// Safely appends a message to the rich edit control from any thread
void LogMessage(const std::string& msg) {
    // If called from a worker thread, post a message. Otherwise, update directly.
    if (GetCurrentThreadId() != GetWindowThreadProcessId(hWnd, NULL)) {
        size_t len = msg.length() + 1;
        char* buf = new char[len];
        strcpy_s(buf, len, msg.c_str());
        PostMessage(hWnd, WM_APP_LOG_MSG, 0, (LPARAM)buf);
    }
    else {
        // Correct way to append text
        CHARRANGE cr;
        cr.cpMin = -1;
        cr.cpMax = -1;
        SendMessage(hLog, EM_EXSETSEL, 0, (LPARAM)&cr);
        SendMessage(hLog, EM_REPLACESEL, 0, (LPARAM)msg.c_str());
    }
}

// Worker thread to handle the protection process
unsigned __stdcall ProtectionThread(void* pArguments) {
    ThreadParams* params = static_cast<ThreadParams*>(pArguments);
    ProtectorSettings settings;
    // settings.enable_anti_debugging = false; // Example of changing a setting

    try {
        std::string protected_dll = params->dll_path + ".protected";
        std::string protected_meta = params->metadata_path + ".protected";

        LogMessage("Step 1/4: Encrypting DLL...\n");
        if (!encrypt_file(params->dll_path, protected_dll)) {
            throw std::runtime_error("Failed to encrypt DLL file.");
        }

        LogMessage("Step 2/4: Encrypting Metadata...\n");
        if (!encrypt_file(params->metadata_path, protected_meta)) {
            throw std::runtime_error("Failed to encrypt metadata file.");
        }

        LogMessage("Step 3/4: Virtualizing function at RVA " + to_hex_string(params->function_rva) + "...\n");
        protect_function(params->dll_path, params->function_rva, settings);

        LogMessage("Step 4/4: Generating loader executable...\n");
        generate_loader(protected_dll, protected_meta, settings);

        LogMessage("\nProtection successful! ✅\n");
        LogMessage("Protected DLL: " + protected_dll + "\n");
        LogMessage("Protected Metadata: " + protected_meta + "\n");
    }
    catch (const std::exception& e) {
        LogMessage("\nERROR: " + std::string(e.what()) + "\n");
    }
    catch (...) {
        LogMessage("\nAn unknown critical error occurred. ❌\n");
    }

    // Re-enable the button and clean up
    EnableWindow(hBtnProtect, TRUE);
    delete params;
    return 0;
}