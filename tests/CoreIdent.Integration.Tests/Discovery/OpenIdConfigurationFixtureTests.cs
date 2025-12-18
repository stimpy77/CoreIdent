using System.Net;
using System.Text.Json;
using CoreIdent.Core.Models;
using CoreIdent.Testing.Fixtures;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Discovery;

public sealed class OpenIdConfigurationFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task Openid_configuration_returns_grant_types_supported_matching_mapped_endpoints()
    {
        using var response = await Client.GetAsync("/.well-known/openid-configuration");

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Discovery endpoint should return 200 OK.");

        var json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace("Discovery endpoint should return a JSON body.");

        using var document = JsonDocument.Parse(json);

        document.RootElement.TryGetProperty("grant_types_supported", out var grantTypesElement)
            .ShouldBeTrue("Discovery document should include grant_types_supported.");

        grantTypesElement.ValueKind.ShouldBe(JsonValueKind.Array, "grant_types_supported should be a JSON array.");

        var grantTypes = grantTypesElement
            .EnumerateArray()
            .Select(x => x.GetString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .ToList();

        grantTypes.Count.ShouldBeGreaterThan(0, "grant_types_supported should be non-empty.");

        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            GrantTypes.ClientCredentials,
            GrantTypes.RefreshToken,
            GrantTypes.AuthorizationCode,
            GrantTypes.Password
        };

        grantTypes.ToHashSet(StringComparer.Ordinal).SetEquals(expected)
            .ShouldBeTrue("grant_types_supported should match the grants supported by the mapped CoreIdent endpoints in the test host.");

        document.RootElement.TryGetProperty("response_types_supported", out var responseTypesElement)
            .ShouldBeTrue("Discovery document should include response_types_supported when authorization endpoint is mapped.");
        responseTypesElement.ValueKind.ShouldBe(JsonValueKind.Array, "response_types_supported should be a JSON array.");
        responseTypesElement.EnumerateArray()
            .Select(x => x.GetString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .ShouldContain(
                x => string.Equals(x, "code", StringComparison.Ordinal),
                "response_types_supported should include 'code' when authorization endpoint is mapped.");

        document.RootElement.TryGetProperty("token_endpoint_auth_methods_supported", out var authMethodsElement)
            .ShouldBeTrue("Discovery document should include token_endpoint_auth_methods_supported when token endpoint is mapped.");
        authMethodsElement.ValueKind.ShouldBe(JsonValueKind.Array, "token_endpoint_auth_methods_supported should be a JSON array.");
        var methods = authMethodsElement.EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrWhiteSpace(x)).Cast<string>().ToList();
        methods.ShouldContain(
            x => string.Equals(x, "client_secret_basic", StringComparison.Ordinal),
            "token endpoint auth methods should include client_secret_basic.");
        methods.ShouldContain(
            x => string.Equals(x, "client_secret_post", StringComparison.Ordinal),
            "token endpoint auth methods should include client_secret_post.");
    }
}
