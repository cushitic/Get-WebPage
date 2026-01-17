# 1. Define C# code that RETURNS data instead of printing it
$csharpCode = @'
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text; // Required for building the output string

public class WebToolCaptured
{
    // Change return type from 'void' to 'string'
    public static string Download(string url, bool showHeaders)
    {
        return DownloadAsync(url, showHeaders).GetAwaiter().GetResult();
    }

    private static async Task<string> DownloadAsync(string url, bool showHeaders)
    {
        // We use StringBuilder to collect the text
        StringBuilder sb = new StringBuilder();

        using (HttpClient client = new HttpClient())
        {
            try 
            {
                if (showHeaders)
                {
                    HttpResponseMessage response = await client.GetAsync(url);
                    
                    sb.AppendLine(string.Format("Status: {0}", response.StatusCode));
                    
                    foreach (var header in response.Headers)
                    {
                        sb.AppendLine(string.Format("{0}: {1}", header.Key, string.Join(", ", header.Value)));
                    }
                }
                else
                {
                    string content = await client.GetStringAsync(url);
                    
                    sb.AppendLine(string.Format("", url));
                    sb.Append(content);
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("Error: " + ex.Message);
            }
        }
        
        // Return the collected text to PowerShell
        return sb.ToString();
    }
}
'@

# 2. Compile the code
Add-Type -TypeDefinition $csharpCode -Language CSharp -IgnoreWarnings -ReferencedAssemblies "System.Net.Http"

# 3. Create the function
function Get-WebPage {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [switch]$Headers
    )

    # Now the data flows out of C# into the PowerShell pipeline
    return [WebToolCaptured]::Download($Uri, $Headers)
}