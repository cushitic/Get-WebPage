# Get-WebPage

A robust utility to download web pages and inspect HTTP headers. It combines the raw speed and modern standards of C# (`HttpClient`) with the ease of use of PowerShell.

## Features
- **Hybrid Architecture:** Writes C# code directly inside a PowerShell script—no external `.exe` or compilation required.
- **Pipeline Support:** Returns string data directly to the pipeline, allowing you to save to variables or redirect to files (`> file.html`).
- **Download HTML:** Fetch the raw HTML string of any URL.
- **Inspect Headers:** Retrieve status codes and response headers.
- **Modern Standards:** Uses `System.Net.Http.HttpClient` (Async/Await) to prevent UI freezing and ensure efficient networking.

## Getting Started

### Prerequisites
- Windows PowerShell 5.1 or PowerShell Core (pwsh)
- .NET Framework (Pre-installed on most Windows machines)

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/cushitic/Get-WebPage.git](https://github.com/cushitic/Get-WebPage.git)