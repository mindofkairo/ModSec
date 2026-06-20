using System.Net;
using System.Net.Http;
using System.Text;
using ModSec.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using SPT.Common.Http;

namespace ModSec.Services;

public class ModSecServerModule
{
    private static readonly JsonSerializerSettings JsonSettings = new()
    {
        ContractResolver = new CamelCasePropertyNamesContractResolver()
    };

    private readonly HttpClient _httpClient;

    public ModSecServerModule()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.Add("modsec-version", ModSecConstants.Version);
    }

    public async Task<PolicyResponse?> GetPolicy()
    {
        return JsonConvert.DeserializeObject<PolicyResponse>(
            await GetString("/modsec/policy"));
    }

    public async Task<EnforcementResponse?> SendReport(ClientReport report)
    {
        return JsonConvert.DeserializeObject<EnforcementResponse>(
            await PostJson("/modsec/report", report));
    }

    public async Task<EnforcementResponse?> SendHeartbeat(ClientHeartbeat heartbeat)
    {
        return JsonConvert.DeserializeObject<EnforcementResponse>(
            await PostJson("/modsec/heartbeat", heartbeat));
    }

    public async Task<PopupPollResponse?> PollPopups(ClientPopupPoll poll)
    {
        return JsonConvert.DeserializeObject<PopupPollResponse>(
            await PostJson("/modsec/popups", poll));
    }

    private async Task<string> GetString(string path)
    {
        using var response = await _httpClient.GetAsync($"{RequestHandler.Host}{path}");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }

    private async Task<string> PostJson(string path, object body)
    {
        var json = JsonConvert.SerializeObject(body, JsonSettings);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"{RequestHandler.Host}{path}", content);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}
