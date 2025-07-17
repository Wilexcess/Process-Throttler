// Required WinSock2 headers, must be included before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include <set>
#include <atomic>

#include <windows.h>
#include <commctrl.h> // Required for Tab Controls
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <io.h>
#include <fcntl.h>
#include <shellapi.h>
#include <wininet.h>

// Include the WinDivert header
#include "windivert.h"

// Link required libraries
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")

// --- Application Info ---
const std::wstring APP_VERSION = L"v1.3.0";
const std::wstring GITHUB_REPO = L"Wilexcess/Process-Throttler";

// Custom message to signal that background shutdown is complete
#define WM_APP_STOP_COMPLETE (WM_APP + 1)

// --- Global Variables ---
DWORD g_targetPid = 0;
std::atomic<bool> g_isThrottlingActive = false;
std::atomic<bool> g_isDelayActive = false;
std::atomic<bool> g_isTimedModeEnabled = false;
std::atomic<bool> g_exitSignal = false;
std::set<UINT16> g_robloxPorts;
HANDLE g_winDivertHandle = NULL;
std::thread g_workerThread, g_inputThread, g_portDiscoveryThread, g_mouseHookThread;
wchar_t g_iniPath[MAX_PATH];

// --- GUI Handles ---
HWND g_hwnd, g_hTabControl;
HWND g_hProcessNameEdit, g_hProtoTCP, g_hProtoUDP, g_hProtoBoth;
HWND g_hToggleKeyEdit, g_hTimedKeyEdit, g_hTimedModeMsEdit;
HWND g_hInboundCheck, g_hOutboundCheck, g_hBothCheck;
HWND g_hStartButton, g_hStopButton;
HWND g_hTimedModeStatusLabel, g_hStatusLabel, g_hTimedModeExplanationLabel;
HWND g_hEnableTimedModeCheck, g_hAlwaysOnTopCheck, g_hEnableToggleKeyCheck; // NEW
HWND g_hInstructionsText;
std::vector<HWND> g_settingsControls, g_instructionsControls, g_configControls;

// --- Application Settings ---
std::atomic<UINT> g_toggleKey = 'Z';
std::atomic<UINT> g_timedModeToggleKey = 'C';
int g_timedModeMs = 200;
bool g_throttleInbound = true, g_throttleOutbound = false;

// --- Hooks and Subclassing ---
HHOOK g_mouseHook = NULL;
WNDPROC g_originalToggleKeyProc, g_originalTimedKeyProc;

// --- Function Declarations ---
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK KeybindEditProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void create_gui_elements(HWND hwnd);
void update_status(const std::wstring& status, bool isSubStatus = false);
void start_throttling();
void stop_throttling_worker();
void delayed_toggle_on_thread();
void set_config_controls_state(bool enabled, bool stopping = false);
void set_timed_mode_controls_state(bool enabled);
void SaveSettings();
void LoadSettings();
BOOL IsRunningAsAdmin();
void CheckForUpdates();
void SwitchTab(int tabIndex);

DWORD find_pid_by_name(const std::wstring& processName) {
    PROCESSENTRY32 processInfo; processInfo.dwSize = sizeof(processInfo);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    Process32First(hSnapshot, &processInfo);
    if (processName.compare(processInfo.szExeFile) == 0) { CloseHandle(hSnapshot); return processInfo.th32ProcessID; }
    while (Process32Next(hSnapshot, &processInfo)) { if (processName.compare(processInfo.szExeFile) == 0) { CloseHandle(hSnapshot); return processInfo.th32ProcessID; } }
    CloseHandle(hSnapshot); return 0;
}
bool discover_ports_for_pid(DWORD pid) {
    g_robloxPorts.clear(); PMIB_TCPTABLE_OWNER_PID tcpTable = NULL; PMIB_UDPTABLE_OWNER_PID udpTable = NULL;
    DWORD size = 0; size_t tcpPortsFound = 0, udpPortsFound = 0;
    if (GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (tcpTable) { if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) { for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) { if (tcpTable->table[i].dwOwningPid == pid) { g_robloxPorts.insert(ntohs((u_short)tcpTable->table[i].dwLocalPort)); tcpPortsFound++; } } } free(tcpTable); }
    } size = 0;
    if (GetExtendedUdpTable(NULL, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (udpTable) { if (GetExtendedUdpTable(udpTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) { for (DWORD i = 0; i < udpTable->dwNumEntries; i++) { if (udpTable->table[i].dwOwningPid == pid) { g_robloxPorts.insert(ntohs((u_short)udpTable->table[i].dwLocalPort)); udpPortsFound++; } } } free(udpTable); }
    }
    if (g_robloxPorts.empty()) { return false; }
    update_status(L"Discovered " + std::to_wstring(tcpPortsFound) + L" TCP and " + std::to_wstring(udpPortsFound) + L" UDP ports. Ready."); return true;
}
void packet_worker_thread() {
    std::vector<char> packet(65535); UINT packetLen; WINDIVERT_ADDRESS addr; PWINDIVERT_IPHDR ip_header; PWINDIVERT_TCPHDR tcp_header; PWINDIVERT_UDPHDR udp_header;
    while (!g_exitSignal) {
        if (!WinDivertRecv(g_winDivertHandle, packet.data(), (UINT)packet.size(), &packetLen, &addr)) { continue; }
        WinDivertHelperParsePacket(packet.data(), packetLen, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);
        bool is_roblox_packet = false;
        if (tcp_header) { if (g_robloxPorts.count(ntohs(tcp_header->SrcPort)) || g_robloxPorts.count(ntohs(tcp_header->DstPort))) is_roblox_packet = true; }
        else if (udp_header) { if (g_robloxPorts.count(ntohs(udp_header->SrcPort)) || g_robloxPorts.count(ntohs(udp_header->DstPort))) is_roblox_packet = true; }
        if (!is_roblox_packet) { WinDivertSend(g_winDivertHandle, packet.data(), packetLen, NULL, &addr); continue; }
        bool is_inbound = !addr.Outbound;
        if (g_isThrottlingActive.load()) { bool should_drop = (is_inbound && g_throttleInbound) || (!is_inbound && g_throttleOutbound); if (should_drop) { continue; } }
        WinDivertSend(g_winDivertHandle, packet.data(), packetLen, NULL, &addr);
    }
}
void delayed_toggle_on_thread() {
    g_isDelayActive = true; update_status(L"Waiting " + std::to_wstring(g_timedModeMs) + L"ms...", true);
    std::this_thread::sleep_for(std::chrono::milliseconds(g_timedModeMs));
    if (g_isDelayActive.load() && !g_exitSignal.load()) { g_isThrottlingActive = true; update_status(L"Packet drop ENABLED"); }
    g_isDelayActive = false;
}
void input_handler_thread() {
    bool toggle_key_down = false, timed_key_down = false;
    while (!g_exitSignal) {
        if (IsDlgButtonChecked(g_hwnd, 403)) { // Check if instant toggle is enabled
            if (GetAsyncKeyState(g_toggleKey.load()) & 0x8000) {
                if (!toggle_key_down) { g_isThrottlingActive = !g_isThrottlingActive; update_status(g_isThrottlingActive ? L"Packet drop ENABLED" : L"Packet drop DISABLED"); }
                toggle_key_down = true;
            }
            else { toggle_key_down = false; }
        }
        else { toggle_key_down = false; }
        if (IsDlgButtonChecked(g_hwnd, 401)) {
            if (GetAsyncKeyState(g_timedModeToggleKey.load()) & 0x8000) {
                if (!timed_key_down) {
                    g_isTimedModeEnabled = !g_isTimedModeEnabled;
                    if (!g_isTimedModeEnabled.load() && g_isThrottlingActive.load()) { g_isThrottlingActive = false; update_status(L"Packet drop DISABLED"); }
                    update_status(g_isTimedModeEnabled ? L"Timed Mode: ON (Click to use)" : L"Timed Mode: OFF", true);
                }
                timed_key_down = true;
            }
            else { timed_key_down = false; }
        }
        else { timed_key_down = false; }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_LBUTTONDOWN) {
        if (g_isTimedModeEnabled.load()) {
            if (g_isThrottlingActive.load()) { g_isThrottlingActive = false; update_status(L"Packet drop DISABLED"); }
            else if (g_isDelayActive.load()) { g_isDelayActive = false; update_status(L"Timed activation canceled.", true); }
            else {
                wchar_t buffer[10]; GetWindowText(g_hTimedModeMsEdit, buffer, 10); g_timedModeMs = _wtoi(buffer); if (g_timedModeMs < 1) g_timedModeMs = 1;
                std::thread(delayed_toggle_on_thread).detach();
            }
        }
    } return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
}
void mouse_hook_thread() {
    g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, GetModuleHandle(NULL), 0);
    MSG msg; while (GetMessage(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessage(&msg); }
    UnhookWindowsHookEx(g_mouseHook);
}
void port_discovery_loop() {
    while (!g_exitSignal) { if (g_targetPid != 0) discover_ports_for_pid(g_targetPid); std::this_thread::sleep_for(std::chrono::seconds(5)); }
}
BOOL IsRunningAsAdmin() {
    BOOL fIsAdmin = FALSE; HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation; DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) { fIsAdmin = Elevation.TokenIsElevated; }
    } if (hToken) { CloseHandle(hToken); } return fIsAdmin;
}
void CheckForUpdates() {
    HINTERNET hInternet = InternetOpen(L"ProcessThrottlerUpdateChecker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        std::wstring url = L"https://api.github.com/repos/" + GITHUB_REPO + L"/releases/latest";
        HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
        if (hConnect) {
            char buffer[4096]; DWORD bytesRead = 0; std::string response;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) { buffer[bytesRead] = '\0'; response += buffer; }
            InternetCloseHandle(hConnect);
            std::string tagNameKey = "\"tag_name\":\"";
            size_t start = response.find(tagNameKey);
            if (start != std::string::npos) {
                start += tagNameKey.length(); size_t end = response.find("\"", start);
                if (end != std::string::npos) {
                    std::string latestVersionStr = response.substr(start, end - start);
                    std::wstring latestVersion(latestVersionStr.begin(), latestVersionStr.end());
                    if (APP_VERSION.compare(latestVersion) != 0) {
                        std::wstring message = L"A new version is available!\n\nYour version: " + APP_VERSION + L"\nLatest version: " + latestVersion + L"\n\nGo to download page?";
                        if (MessageBox(NULL, message.c_str(), L"Update Available", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
                            std::wstring downloadUrl = L"https://github.com/" + GITHUB_REPO + L"/releases/latest";
                            ShellExecute(NULL, L"open", downloadUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
                        }
                    }
                }
            }
        }
        InternetCloseHandle(hInternet);
    }
}
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int nShowCmd) {
    if (!IsRunningAsAdmin()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = L"runas"; sei.lpFile = szPath; sei.hwnd = NULL; sei.nShow = SW_NORMAL;
            if (ShellExecuteEx(&sei)) { return 0; }
            else { MessageBox(NULL, L"This application requires administrator privileges.", L"Elevation Failed", MB_OK | MB_ICONERROR); return 1; }
        } return 1;
    }
    GetModuleFileName(NULL, g_iniPath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(g_iniPath, L'\\');
    if (lastSlash) { *(lastSlash + 1) = L'\0'; wcscat_s(g_iniPath, MAX_PATH, L"config.ini"); }
    std::thread(CheckForUpdates).detach();
    const wchar_t CLASS_NAME[] = L"ProcessThrottlerWindowClass"; WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc; wc.hInstance = hInstance; wc.lpszClassName = CLASS_NAME; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);
    std::wstring windowTitle = L"Process Throttler " + APP_VERSION;
    g_hwnd = CreateWindowEx(0, CLASS_NAME, windowTitle.c_str(), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 500, 580, NULL, NULL, hInstance, NULL);
    if (g_hwnd == NULL) return 0;
    create_gui_elements(g_hwnd); LoadSettings();
    ShowWindow(g_hwnd, nShowCmd);
    MSG msg = { }; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
LRESULT CALLBACK KeybindEditProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_KEYDOWN: {
        UINT vkCode = (UINT)wParam; wchar_t keyName[50]; LONG scanCode = (lParam >> 16) & 0xFF;
        if (vkCode == VK_SHIFT || vkCode == VK_CONTROL || vkCode == VK_MENU) { scanCode |= 0x100; }
        GetKeyNameText(scanCode << 16, keyName, sizeof(keyName) / sizeof(wchar_t));
        if (hwnd == g_hToggleKeyEdit) { g_toggleKey = vkCode; }
        else if (hwnd == g_hTimedKeyEdit) { g_timedModeToggleKey = vkCode; }
        SetWindowText(hwnd, keyName); return 0;
    }
    case WM_CHAR: case WM_KEYUP: return 0;
    }
    if (hwnd == g_hToggleKeyEdit) { return CallWindowProc(g_originalToggleKeyProc, hwnd, uMsg, wParam, lParam); }
    return CallWindowProc(g_originalTimedKeyProc, hwnd, uMsg, wParam, lParam);
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_DESTROY: SaveSettings(); stop_throttling_worker(); PostQuitMessage(0); return 0;
    case WM_APP_STOP_COMPLETE:
        update_status(L"Stopped. Ready to start.");
        set_config_controls_state(true, false);
        return 0;
    case WM_NOTIFY: // Handle tab switching
        if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
            int selectedTab = TabCtrl_GetCurSel(g_hTabControl);
            SwitchTab(selectedTab);
        }
        break;
    case WM_COMMAND: {
        if (HIWORD(wParam) == BN_CLICKED) {
            HWND hButtonClicked = (HWND)lParam;
            if (hButtonClicked == g_hStartButton) { start_throttling(); }
            else if (hButtonClicked == g_hStopButton) {
                g_isThrottlingActive = false; update_status(L"Stopping...");
                set_config_controls_state(false, true);
                std::thread(stop_throttling_worker).detach();
            }
            else if (hButtonClicked == g_hEnableTimedModeCheck) { set_timed_mode_controls_state(IsDlgButtonChecked(hwnd, 401)); }
            else if (hButtonClicked == g_hAlwaysOnTopCheck) { SetWindowPos(hwnd, IsDlgButtonChecked(hwnd, 402) ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); }
            else if (hButtonClicked == g_hInboundCheck || hButtonClicked == g_hOutboundCheck) {
                g_throttleInbound = IsDlgButtonChecked(hwnd, 201); g_throttleOutbound = IsDlgButtonChecked(hwnd, 202);
                CheckDlgButton(hwnd, 203, (g_throttleInbound && g_throttleOutbound) ? BST_CHECKED : BST_UNCHECKED);
            }
            else if (hButtonClicked == g_hBothCheck) {
                bool is_checked = IsDlgButtonChecked(hwnd, 203); g_throttleInbound = is_checked; g_throttleOutbound = is_checked;
                CheckDlgButton(hwnd, 201, is_checked ? BST_CHECKED : BST_UNCHECKED); CheckDlgButton(hwnd, 202, is_checked ? BST_CHECKED : BST_UNCHECKED);
            }
        }
        return 0;
    }
    case WM_PAINT: { PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps); FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1)); EndPaint(hwnd, &ps); } return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
void create_gui_elements(HWND hwnd) {
    // Main Tab Control
    g_hTabControl = CreateWindow(WC_TABCONTROL, L"", WS_CHILD | WS_VISIBLE, 5, 5, 470, 470, hwnd, NULL, NULL, NULL);
    TCITEM tie;
    tie.mask = TCIF_TEXT;
    tie.pszText = (LPWSTR)L"Settings";
    TabCtrl_InsertItem(g_hTabControl, 0, &tie);
    tie.pszText = (LPWSTR)L"Instructions";
    TabCtrl_InsertItem(g_hTabControl, 1, &tie);

    int y = 40; // Y-position for controls inside the tab
    const int ITEM_HEIGHT = 20; const int LABEL_WIDTH = 145; const int EDIT_WIDTH = 100;
    const int ROW_GAP = 28; const int GROUP_GAP = 35;

    // --- Settings Tab Controls ---
    g_settingsControls.push_back(CreateWindow(L"STATIC", L"Process Name:", WS_CHILD, 10, y, LABEL_WIDTH, ITEM_HEIGHT, hwnd, NULL, NULL, NULL));
    g_hProcessNameEdit = CreateWindow(L"EDIT", L"RobloxPlayerBeta.exe", WS_CHILD | WS_BORDER, 160, y, 295, ITEM_HEIGHT, hwnd, NULL, NULL, NULL);
    y += ROW_GAP;
    g_hProtoTCP = CreateWindow(L"BUTTON", L"TCP", WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP, 10, y, 50, ITEM_HEIGHT, hwnd, (HMENU)301, NULL, NULL);
    g_hProtoUDP = CreateWindow(L"BUTTON", L"UDP", WS_CHILD | BS_AUTORADIOBUTTON, 70, y, 50, ITEM_HEIGHT, hwnd, (HMENU)302, NULL, NULL);
    g_hProtoBoth = CreateWindow(L"BUTTON", L"Both", WS_CHILD | BS_AUTORADIOBUTTON, 130, y, 60, ITEM_HEIGHT, hwnd, (HMENU)303, NULL, NULL);
    g_settingsControls.push_back(CreateWindow(L"STATIC", L"<- If you're unsure, use Both.", WS_CHILD, 200, y, 255, ITEM_HEIGHT, hwnd, NULL, NULL, NULL));
    y += GROUP_GAP;

    g_hEnableToggleKeyCheck = CreateWindow(L"BUTTON", L"Enable Instant Toggle", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 145, ITEM_HEIGHT, hwnd, (HMENU)403, NULL, NULL);
    y += ROW_GAP;
    g_settingsControls.push_back(CreateWindow(L"STATIC", L"Toggle Keybind:", WS_CHILD, 25, y, 130, ITEM_HEIGHT, hwnd, NULL, NULL, NULL));
    g_hToggleKeyEdit = CreateWindow(L"EDIT", L"Z", WS_CHILD | WS_BORDER | ES_CENTER | ES_READONLY, 160, y, EDIT_WIDTH, ITEM_HEIGHT, hwnd, (HMENU)101, NULL, NULL);
    y += GROUP_GAP;

    g_hEnableTimedModeCheck = CreateWindow(L"BUTTON", L"Enable Timed Mode", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 145, ITEM_HEIGHT, hwnd, (HMENU)401, NULL, NULL);
    y += ROW_GAP;
    g_settingsControls.push_back(CreateWindow(L"STATIC", L"Timed Mode Hotkey:", WS_CHILD, 25, y, 130, ITEM_HEIGHT, hwnd, NULL, NULL, NULL));
    g_hTimedKeyEdit = CreateWindow(L"EDIT", L"C", WS_CHILD | WS_BORDER | ES_CENTER | ES_READONLY, 160, y, EDIT_WIDTH, ITEM_HEIGHT, hwnd, (HMENU)102, NULL, NULL);
    g_hTimedModeStatusLabel = CreateWindow(L"STATIC", L"Timed Mode: OFF", WS_CHILD, 270, y, 185, ITEM_HEIGHT, hwnd, NULL, NULL, NULL);
    y += ROW_GAP;
    g_settingsControls.push_back(CreateWindow(L"STATIC", L"Enter ms:", WS_CHILD, 25, y, 130, ITEM_HEIGHT, hwnd, NULL, NULL, NULL));
    g_hTimedModeMsEdit = CreateWindow(L"EDIT", L"200", WS_CHILD | WS_BORDER, 160, y, 50, ITEM_HEIGHT, hwnd, (HMENU)103, NULL, NULL);
    y += GROUP_GAP;

    g_hInboundCheck = CreateWindow(L"BUTTON", L"Inbound (Used for COM Offset)", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 240, ITEM_HEIGHT, hwnd, (HMENU)201, NULL, NULL);
    y += ROW_GAP;
    g_hOutboundCheck = CreateWindow(L"BUTTON", L"Outbound", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 120, ITEM_HEIGHT, hwnd, (HMENU)202, NULL, NULL);
    y += ROW_GAP;
    g_hBothCheck = CreateWindow(L"BUTTON", L"Both", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 120, ITEM_HEIGHT, hwnd, (HMENU)203, NULL, NULL);
    y += ROW_GAP;
    g_hAlwaysOnTopCheck = CreateWindow(L"BUTTON", L"Always on Top", WS_CHILD | BS_AUTOCHECKBOX, 10, y, 120, ITEM_HEIGHT, hwnd, (HMENU)402, NULL, NULL);
    y += GROUP_GAP + 10;

    // --- Instructions Tab Controls ---
    const wchar_t* instructions =
        L"--- General Use ---\r\n"
        L"1. Enter the process name (e.g., RobloxPlayerBeta.exe).\r\n"
        L"2. Choose your settings and hotkeys.\r\n"
        L"3. Press Start.\r\n\r\n"
        L"--- Instant Mode ---\r\n"
        L"1. Check \"Enable Instant Toggle\".\r\n"
        L"2. Press your \"Toggle Keybind\" to instantly turn the lag on or off.\r\n"
        L"   (This is useful for general purpose lagging).\r\n\r\n"
        L"--- Timed Mode (Gearless Offset) ---\r\n"
        L"This mode is designed for precise actions, like using it for gearless offset of COM.\r\n\r\n"
        L"1. Configure your desired settings & Check \"Enable Timed Mode\".\r\n"
        L"2. Press your \"Timed Mode Hotkey\" to \"ARM\" the system. The status will change to \"ON (Click to use)\".\r\n"
        L"3. In-game, open the menu and hover your mouse over the \"Reset Character\" button.\r\n"
        L"4. Left-click to reset. The lag will activate automatically after the millisecond delay you set.\r\n"
        L"5. To disable the lag, simply click your mouse again.";
    g_hInstructionsText = CreateWindow(L"EDIT", instructions, WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 10, 40, 455, 380, hwnd, NULL, NULL, NULL);

    // --- Shared Controls (Outside Tab) ---
    g_hStatusLabel = CreateWindow(L"STATIC", L"Status: Idle. Press Start.", WS_VISIBLE | WS_CHILD, 10, 475, 445, 40, hwnd, NULL, NULL, NULL);
    g_hStartButton = CreateWindow(L"BUTTON", L"Start", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 130, 505, 100, 30, hwnd, (HMENU)1, NULL, NULL);
    g_hStopButton = CreateWindow(L"BUTTON", L"Stop", WS_VISIBLE | WS_CHILD, 250, 505, 100, 30, hwnd, (HMENU)2, NULL, NULL);

    // Group all controls for easy show/hide
    g_settingsControls.insert(g_settingsControls.end(), { g_hProcessNameEdit, g_hProtoTCP, g_hProtoUDP, g_hProtoBoth, g_hEnableToggleKeyCheck, g_hToggleKeyEdit, g_hEnableTimedModeCheck, g_hTimedKeyEdit, g_hTimedModeStatusLabel, g_hTimedModeMsEdit, g_hInboundCheck, g_hOutboundCheck, g_hBothCheck, g_hAlwaysOnTopCheck });
    g_instructionsControls.push_back(g_hInstructionsText);
    g_configControls = { g_hProcessNameEdit, g_hProtoTCP, g_hProtoUDP, g_hProtoBoth, g_hEnableToggleKeyCheck, g_hToggleKeyEdit, g_hEnableTimedModeCheck, g_hTimedKeyEdit, g_hTimedModeMsEdit, g_hAlwaysOnTopCheck };

    EnableWindow(g_hStopButton, FALSE);
    g_originalToggleKeyProc = (WNDPROC)SetWindowLongPtr(g_hToggleKeyEdit, GWLP_WNDPROC, (LONG_PTR)KeybindEditProc);
    g_originalTimedKeyProc = (WNDPROC)SetWindowLongPtr(g_hTimedKeyEdit, GWLP_WNDPROC, (LONG_PTR)KeybindEditProc);
    SwitchTab(0); // Show settings tab by default
}
void SaveSettings() {
    wchar_t buffer[256];
    GetWindowText(g_hProcessNameEdit, buffer, 256); WritePrivateProfileString(L"Settings", L"ProcessName", buffer, g_iniPath);
    int protocol = IsDlgButtonChecked(g_hwnd, 301) ? 0 : (IsDlgButtonChecked(g_hwnd, 302) ? 1 : 2);
    wsprintf(buffer, L"%d", protocol); WritePrivateProfileString(L"Settings", L"Protocol", buffer, g_iniPath);
    wsprintf(buffer, L"%u", g_toggleKey.load()); WritePrivateProfileString(L"Settings", L"ToggleKey", buffer, g_iniPath);
    wsprintf(buffer, L"%u", g_timedModeToggleKey.load()); WritePrivateProfileString(L"Settings", L"TimedKey", buffer, g_iniPath);
    GetWindowText(g_hTimedModeMsEdit, buffer, 256); WritePrivateProfileString(L"Settings", L"TimedMs", buffer, g_iniPath);
    wsprintf(buffer, L"%d", IsDlgButtonChecked(g_hwnd, 201) ? 1 : 0); WritePrivateProfileString(L"Settings", L"BlockInbound", buffer, g_iniPath);
    wsprintf(buffer, L"%d", IsDlgButtonChecked(g_hwnd, 202) ? 1 : 0); WritePrivateProfileString(L"Settings", L"BlockOutbound", buffer, g_iniPath);
    wsprintf(buffer, L"%d", IsDlgButtonChecked(g_hwnd, 401) ? 1 : 0); WritePrivateProfileString(L"Settings", L"EnableTimedMode", buffer, g_iniPath);
    wsprintf(buffer, L"%d", IsDlgButtonChecked(g_hwnd, 402) ? 1 : 0); WritePrivateProfileString(L"Settings", L"AlwaysOnTop", buffer, g_iniPath);
    wsprintf(buffer, L"%d", IsDlgButtonChecked(g_hwnd, 403) ? 1 : 0); WritePrivateProfileString(L"Settings", L"EnableToggleKey", buffer, g_iniPath);
}
void LoadSettings() {
    wchar_t buffer[256]; wchar_t keyName[50];
    GetPrivateProfileString(L"Settings", L"ProcessName", L"RobloxPlayerBeta.exe", buffer, 256, g_iniPath); SetWindowText(g_hProcessNameEdit, buffer);
    int protocol = GetPrivateProfileInt(L"Settings", L"Protocol", 2, g_iniPath);
    if (protocol == 0) CheckDlgButton(g_hwnd, 301, BST_CHECKED); else if (protocol == 1) CheckDlgButton(g_hwnd, 302, BST_CHECKED); else CheckDlgButton(g_hwnd, 303, BST_CHECKED);
    UINT vkCode = GetPrivateProfileInt(L"Settings", L"ToggleKey", 'Z', g_iniPath); g_toggleKey = vkCode;
    GetKeyNameText(MapVirtualKey(vkCode, MAPVK_VK_TO_VSC) << 16, keyName, sizeof(keyName) / sizeof(wchar_t)); SetWindowText(g_hToggleKeyEdit, keyName);
    vkCode = GetPrivateProfileInt(L"Settings", L"TimedKey", 'C', g_iniPath); g_timedModeToggleKey = vkCode;
    GetKeyNameText(MapVirtualKey(vkCode, MAPVK_VK_TO_VSC) << 16, keyName, sizeof(keyName) / sizeof(wchar_t)); SetWindowText(g_hTimedKeyEdit, keyName);
    int timedMs = GetPrivateProfileInt(L"Settings", L"TimedMs", 200, g_iniPath); wsprintf(buffer, L"%d", timedMs); SetWindowText(g_hTimedModeMsEdit, buffer);
    bool blockInbound = GetPrivateProfileInt(L"Settings", L"BlockInbound", 1, g_iniPath) == 1;
    bool blockOutbound = GetPrivateProfileInt(L"Settings", L"BlockOutbound", 0, g_iniPath) == 1;
    CheckDlgButton(g_hwnd, 201, blockInbound ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hwnd, 202, blockOutbound ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(g_hwnd, 203, (blockInbound && blockOutbound) ? BST_CHECKED : BST_UNCHECKED);
    g_throttleInbound = blockInbound; g_throttleOutbound = blockOutbound;
    bool enableTimed = GetPrivateProfileInt(L"Settings", L"EnableTimedMode", 1, g_iniPath) == 1;
    CheckDlgButton(g_hwnd, 401, enableTimed ? BST_CHECKED : BST_UNCHECKED); set_timed_mode_controls_state(enableTimed);
    bool alwaysOnTop = GetPrivateProfileInt(L"Settings", L"AlwaysOnTop", 1, g_iniPath) == 1;
    CheckDlgButton(g_hwnd, 402, alwaysOnTop ? BST_CHECKED : BST_UNCHECKED);
    if (alwaysOnTop) { SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE); }
    bool enableToggle = GetPrivateProfileInt(L"Settings", L"EnableToggleKey", 1, g_iniPath) == 1;
    CheckDlgButton(g_hwnd, 403, enableToggle ? BST_CHECKED : BST_UNCHECKED);
}
void update_status(const std::wstring& status, bool isSubStatus) {
    if (isSubStatus) { SetWindowText(g_hTimedModeStatusLabel, status.c_str()); }
    else { SetWindowText(g_hStatusLabel, (L"Status: " + status).c_str()); }
}
void set_config_controls_state(bool enabled, bool stopping) {
    for (HWND hControl : g_configControls) { EnableWindow(hControl, enabled); }
    if (enabled) { set_timed_mode_controls_state(IsDlgButtonChecked(g_hwnd, 401)); }
    else { set_timed_mode_controls_state(false); }
    EnableWindow(g_hStartButton, enabled);
    EnableWindow(g_hStopButton, !enabled);
    if (stopping) { EnableWindow(g_hStopButton, FALSE); }
}
void set_timed_mode_controls_state(bool enabled) {
    EnableWindow(g_hTimedKeyEdit, enabled);
    EnableWindow(g_hTimedModeMsEdit, enabled);
    // Note: Explanation Label is now part of the settings controls and handled by the main function
}
void start_throttling() {
    wchar_t buffer[256]; GetWindowText(g_hProcessNameEdit, buffer, 256); std::wstring processName = buffer;
    update_status(L"Searching for process: " + processName); g_targetPid = find_pid_by_name(processName);
    if (g_targetPid == 0) { update_status(L"Process not found. Please start it and try again."); return; }
    update_status(L"Found " + processName + L" (PID: " + std::to_wstring(g_targetPid) + L"). Discovering ports...");
    const char* filter = IsDlgButtonChecked(g_hwnd, 301) ? "tcp" : (IsDlgButtonChecked(g_hwnd, 302) ? "udp" : "tcp or udp");
    g_winDivertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_winDivertHandle == INVALID_HANDLE_VALUE) { update_status(GetLastError() == 5 ? L"Error: Must be run as Administrator." : L"Error: WinDivert failed. Code: " + std::to_wstring(GetLastError())); return; }
    g_exitSignal = false;
    set_config_controls_state(false);
    g_workerThread = std::thread(packet_worker_thread); g_inputThread = std::thread(input_handler_thread);
    g_portDiscoveryThread = std::thread(port_discovery_loop); g_mouseHookThread = std::thread(mouse_hook_thread);
}
void stop_throttling_worker() {
    g_exitSignal = true;
    if (g_mouseHook) { PostThreadMessageW(GetThreadId(g_mouseHookThread.native_handle()), WM_QUIT, 0, 0); g_mouseHook = NULL; }
    if (g_winDivertHandle) { WinDivertClose(g_winDivertHandle); g_winDivertHandle = NULL; }
    if (g_workerThread.joinable()) g_workerThread.join(); if (g_inputThread.joinable()) g_inputThread.join();
    if (g_portDiscoveryThread.joinable()) g_portDiscoveryThread.join(); if (g_mouseHookThread.joinable()) g_mouseHookThread.join();
    PostMessage(g_hwnd, WM_APP_STOP_COMPLETE, 0, 0);
}
// *** NEW *** Manages showing and hiding controls when switching tabs.
void SwitchTab(int tabIndex) {
    for (HWND hControl : g_settingsControls) { ShowWindow(hControl, tabIndex == 0 ? SW_SHOW : SW_HIDE); }
    for (HWND hControl : g_instructionsControls) { ShowWindow(hControl, tabIndex == 1 ? SW_SHOW : SW_HIDE); }
}
