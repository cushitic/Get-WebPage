# Get-WebPage (Portable)

A self-contained, portable utility to capture dynamic web pages using PowerShell 7 and Selenium.

## 📦 Tech Stack & Versions
This tool runs in a completely isolated environment (Portable Mode). The following versions are bundled or required:

| Component | Version | Notes |
| :--- | :--- | :--- |
| **PowerShell Core** | **7.4.6** (LTS) | Portable x64 edition. No installation required. |
| **Selenium WebDriver** | **4.18.1** | .NET Standard 2.0 version. |
| **Newtonsoft.Json** | **13.0.3** | Required for data serialization. |
| **System.Drawing.Common** | **4.7.2** | Required for Selenium graphical operations. |
| **Edge Driver** | **143.0.3650.139** | *Must match the Edge Browser version installed on the host machine.* |

## 🚀 Quick Start

1. **Unzip** the folder to any location (USB drive, Desktop, etc.).
2. **Double-click** `Launch_Console.bat`.
   - This opens a portable PowerShell 7 terminal with the tool pre-loaded.
3. **Run the command:**
   ```powershell
   Get-WebPage -Uri "google.com"