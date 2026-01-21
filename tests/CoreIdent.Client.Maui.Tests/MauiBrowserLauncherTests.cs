using CoreIdent.Client.Maui;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Maui.Tests;

public sealed class MauiBrowserLauncherTests
{
    [Fact]
    public async Task WebAuthenticator_flow_completes_successfully()
    {
        var response = new AuthenticatorResponse(
            new Dictionary<string, string>
            {
                ["code"] = "abc",
                ["state"] = "xyz"
            },
            AccessToken: null);

        var authenticator = new FakeWebAuthenticatorAdapter(response);
        var sut = new MauiBrowserLauncher(authenticator);

        var result = await sut.LaunchAsync(
            "https://authority.example/auth/authorize?client_id=client",
            "myapp://callback");

        result.IsSuccess.ShouldBeTrue("Browser result should indicate success.");
        result.ResponseUrl.ShouldNotBeNullOrWhiteSpace("Browser result should include a response URL.");

        var query = ParseQuery(result.ResponseUrl!);
        query["code"].ShouldBe("abc", "Authorization code should be included in the response URL.");
        query["state"].ShouldBe("xyz", "State should be included in the response URL.");
    }

    private sealed class FakeWebAuthenticatorAdapter(AuthenticatorResponse response) : IMauiWebAuthenticatorAdapter
    {
        public Task<AuthenticatorResponse> AuthenticateAsync(Uri url, Uri callbackUri, CancellationToken ct = default)
        {
            return Task.FromResult(response);
        }
    }

    private static Dictionary<string, string> ParseQuery(string url)
    {
        var uri = new Uri(url);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var trimmed = uri.Query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return result;
        }

        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kvp = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(kvp[0]);
            var value = kvp.Length == 2 ? Uri.UnescapeDataString(kvp[1]) : string.Empty;
            result[key] = value;
        }

        return result;
    }
}
