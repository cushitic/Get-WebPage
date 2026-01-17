# Get-WebPage.ps1
# Portable PowerShell 7 Version
# Updated: No Regex used for URL cleaning

function Get-WebPage {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [int]$WaitSeconds = 5
    )

    # ---------------------------------------------------------
    # 1. URL SANITIZATION (String Method Version)
    # ---------------------------------------------------------
    
    # A. Handle Markdown Links: [Link Text](https://url.com)
    #    Logic: If it contains "](" and ends with ")", we split it.
    if ($Uri.Contains("](") -and $Uri.EndsWith(")")) {
        $parts = $Uri.Split(@("]("), [System.StringSplitOptions]::None)
        # Take the part after "](" and remove the trailing ")"
        if ($parts.Count -gt 1) {
            $Uri = $parts[1].TrimEnd(")")
        }
    }

    # B. Cleanup common dirty characters
    #    We manually replace brackets, parens, and quotes.
    $Uri = $Uri.Replace("[", "").Replace("]", "")
    $Uri = $Uri.Replace("(", "").Replace(")", "")
    $Uri = $Uri.Replace('"', "").Replace("'", "")
    $Uri = $Uri.Trim()

    # C. Auto-Add HTTPS
    #    Check if it starts with http/https (Case insensitive)
    if (-not $Uri.StartsWith("http", [System.StringComparison]::OrdinalIgnoreCase)) {
        $Uri = "https://" + $Uri
    }

    # Debug: Show the cleaned URL
    Write-Host "Target URL: $Uri" -ForegroundColor DarkGray

    # ---------------------------------------------------------
    # 2. AUTO-LOAD DEPENDENCIES (Root Folder)
    # ---------------------------------------------------------
    $root = $PSScriptRoot
    
    try {
        Add-Type -Path (Join-Path $root "System.Drawing.Common.dll") -ErrorAction Stop
        Add-Type -Path (Join-Path $root "Newtonsoft.Json.dll") -ErrorAction Stop
        Add-Type -Path (Join-Path $root "WebDriver.dll") -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to load dependencies. Ensure DLLs are in: $root"
        return
    }

    # ---------------------------------------------------------
    # 3. CONFIGURE EDGE
    # ---------------------------------------------------------
    $driverPath = Join-Path $root "msedgedriver.exe"
    if (-not (Test-Path $driverPath)) { Write-Error "Missing msedgedriver.exe"; return }

    $options = New-Object OpenQA.Selenium.Edge.EdgeOptions
    $options.AddArgument("--headless=new")
    $options.AddArgument("--disable-gpu")
    $options.AddArgument("--log-level=3")

    $service = [OpenQA.Selenium.Edge.EdgeDriverService]::CreateDefaultService($root)
    $service.HideCommandPromptWindow = $true

    try {
        $driver = New-Object OpenQA.Selenium.Edge.EdgeDriver($service, $options)
        $driver.Navigate().GoToUrl($Uri)
        
        if ($WaitSeconds -gt 0) { Start-Sleep -Seconds $WaitSeconds }
        return $driver.PageSource
    }
    catch { Write-Error $_.Exception.Message }
    finally { if ($driver) { $driver.Quit() } }
}
