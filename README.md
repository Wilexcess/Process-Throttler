# Process Throttler

Process Throttler is a simple but powerful lag switch for Windows games and applications. It gives you fine-tuned control over your connection by letting you selectively block internet traffic for a specific program using hotkeys and other activation methods.

![Screenshot of the application](https://i.imgur.com/0Q8Us6i.png)  

## Features

*   **GUI Interface:** Easy-to-use graphical interface. No command-line needed.
*   **Target Any Process:** Find and target any running application by its process name (e.g., `RobloxPlayerBeta.exe`).
*   **Selective Filtering:** Choose to block only `TCP`, `UDP`, or `Both` types of traffic.
*   **Directional Throttling:** Block `Inbound` traffic, `Outbound` traffic, or both.
*   **Instant Toggle:** Use a customizable hotkey to instantly enable or disable the packet drop.
*   **Timed Mode:**
    *   Enable a special mode with its own hotkey.
    *   When this mode is active, your **mouse click** acts as the trigger.
    *   The first click starts a timer; after your chosen delay (in ms), the packet drop activates.
    *   A second click instantly deactivates it..
*   **Dynamic Port Discovery:** Automatically finds the network ports used by the target application and updates them periodically.
*   **Config Saving:** Automatically save options you have entered to an INI file.

## How to Use

1.  **Download:** Go to the [Releases](https://github.com/Wilexcess/Process-Throttler/releases) page and download the latest version.
2.  **Unzip:** Extract the contents of the `.zip` file into a new folder.
4.  **Run as Administrator:** Right-click `ProcessThrottler.exe` and select "Run as administrator". This is required for WinDivert to capture network traffic.
5.  **Configure:**
    *   Enter the process name you want to target.
    *   Set your preferred hotkeys.
    *   Choose your desired settings.
6.  **Start:** Press the "Start" button. The tool will find the process and its ports.
7.  **Toggle:** Use your hotkeys or mouse clicks to control the packet drop!

## Troubleshooting

### Error: "WinDivert failed. Code: 2"

This is the most common issue and is easy to fix. `Error Code 2` means **File Not Found**. It means the program could not find the `WinDivert.sys` driver file.

**Solution:** Ensure that `WinDivert.dll` and `WinDivert.sys` are in the **same directory** as `ProcessThrottler.exe`.

If the problem persists even after placing the files correctly, you may have a "stuck" driver service. To fix this:
1.  Close the Process Throttler application.
2.  Open a **Command Prompt as Administrator**.
3.  Type the following commands, pressing Enter after each one:
    ```cmd
    sc stop WinDivert
    sc delete WinDivert
    ```
4.  **Reboot your computer.** This is a critical step. (Note: sometimes it may work without a reboot)
5.  After rebooting, try running Process Throttler again (as administrator).

## Building from Source

## 🛠️ If You Want to Build the Project Yourself

To compile and run the project manually, follow these steps:

### ✅ Environment
- Use **Visual Studio 2019** or **2022** (Community Edition is fine).
- Make sure the **"Desktop Development with C++"** workload is installed.  
  You can add it via the Visual Studio Installer if needed.

### 📦 WinDivert SDK
1. Download the latest WinDivert SDK from:  
   https://reqrypt.org/windivert.html

2. From the extracted SDK, copy the following files into your project folder:
   - `include/windivert.h` → put it in an `include/` folder inside your project.
   - `x64/WinDivert.lib` or `x86/WinDivert.lib` → put it in a `lib/` folder.
   - `x64/WinDivert.dll` or `x86/WinDivert.dll` → place next to your `.exe` after build (i.e., in `Debug/` or `Release/`).

3. Make sure the architecture of the `.lib` and `.dll` (x64 or x86) matches your project’s target platform.

### ⚙️ Visual Studio Configuration

#### VC++ Directories:
- **Include Directories**:  
  ```
  $(ProjectDir)include
  ```
- **Library Directories**:  
  ```
  $(ProjectDir)lib
  ```

#### Linker → Input → Additional Dependencies:
Add the following libraries:
```
WinDivert.lib
ws2_32.lib
iphlpapi.lib
```

These are required for packet interception and network API support.

### 🧪 Final Notes:
- Run Visual Studio as **Administrator**, or opening a WinDivert handle will fail with error code 5.
- Ensure the `WinDivert.dll` and `WinDivert64.sys` are next to your compiled `.exe` at runtime.
- Always match the **platform target** (x64/x86) with the version of `WinDivert.lib` and `WinDivert.dll` you’re using.



## Disclaimer

This tool is intended for educational and research purposes. Misusing it to gain an unfair advantage in online games or to disrupt services may violate the terms of service of those applications. Use it responsibly.
