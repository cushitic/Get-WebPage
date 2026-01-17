static async Task GetPageWithChecks()
{
    string url = "https://www.example.com";

    // GetAsync fetches the response metadata (headers/status) but not the body yet
    HttpResponseMessage response = await client.GetAsync(url);

    // This throws an exception if the status code is NOT 200-299
    response.EnsureSuccessStatusCode(); 

    // Now read the content
    string content = await response.Content.ReadAsStringAsync();
    
    Console.WriteLine($"Status Code: {response.StatusCode}");
    Console.WriteLine($"Content Length: {content.Length}");
}