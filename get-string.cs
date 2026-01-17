using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    // 1. Instantiate ONCE (Static)
    private static readonly HttpClient client = new HttpClient();

    static async Task Main()
    {
        string url = "https://www.example.com";

        try
        {
            // 2. Use GetStringAsync for simple text fetching
            string responseBody = await client.GetStringAsync(url);

            Console.WriteLine("Success!");
            Console.WriteLine(responseBody.Substring(0, 100)); // Print first 100 chars
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Request error: {e.Message}");
        }
    }
}

