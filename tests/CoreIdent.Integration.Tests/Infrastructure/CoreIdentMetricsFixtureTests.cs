using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Infrastructure;

public sealed class CoreIdentMetricsFixtureTests : CoreIdentTestFixture
{
    protected override void ConfigureFactory(CoreIdentWebApplicationFactory factory)
    {
        factory.ConfigureTestServices = services =>
        {
            services.AddCoreIdentMetrics();
        };
    }

    [Fact]
    public async Task Token_endpoint_emits_token_issued_and_client_authenticated_metrics()
    {
        await CreateClientAsync(c =>
            c.WithClientId("metrics-client")
                .AsConfidentialClient("metrics-secret")
                .WithGrantTypes(GrantTypes.ClientCredentials)
                .WithScopes("api"));

        var measurements = new ConcurrentBag<Measurement>();

        using var listener = CreateListener(measurements);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["scope"] = "api"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("metrics-client:metrics-secret")));

        var response = await Client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Token endpoint should return 200 OK.");

        await WaitForAsync(
            () => measurements.Any(m => m.Name == "coreident.token.issued"),
            timeout: TimeSpan.FromSeconds(2));

        measurements.Any(m =>
                m.Name == "coreident.client.authenticated"
                && m.Tags.TryGetValue("success", out var success)
                && success is true)
            .ShouldBeTrue("Expected coreident.client.authenticated metric with success=true.");

        measurements.Any(m =>
                m.Name == "coreident.token.issued"
                && m.Tags.TryGetValue("token_type", out var tokenType)
                && (tokenType as string) == "access_token"
                && m.Tags.TryGetValue("grant_type", out var grantType)
                && (grantType as string) == GrantTypes.ClientCredentials)
            .ShouldBeTrue("Expected coreident.token.issued metric for access_token + client_credentials.");
    }

    [Fact]
    public async Task Revoke_endpoint_emits_token_revoked_metric_for_access_token()
    {
        await CreateClientAsync(c =>
            c.WithClientId("metrics-client2")
                .AsConfidentialClient("metrics-secret2")
                .WithGrantTypes(GrantTypes.ClientCredentials)
                .WithScopes("api"));

        var token = await IssueAccessTokenAsync("metrics-client2", "metrics-secret2");

        var measurements = new ConcurrentBag<Measurement>();

        using var listener = CreateListener(measurements);

        using var revokeRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token,
                ["token_type_hint"] = "access_token"
            })
        };

        revokeRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("metrics-client2:metrics-secret2")));

        var revokeResponse = await Client.SendAsync(revokeRequest);

        revokeResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "Revocation endpoint should return 200 OK.");

        await WaitForAsync(
            () => measurements.Any(m => m.Name == "coreident.token.revoked"),
            timeout: TimeSpan.FromSeconds(2));

        measurements.Any(m =>
                m.Name == "coreident.token.revoked"
                && m.Tags.TryGetValue("token_type", out var tokenType)
                && (tokenType as string) == "access_token")
            .ShouldBeTrue("Expected coreident.token.revoked metric for access_token.");
    }

    private static MeterListener CreateListener(ConcurrentBag<Measurement> measurements)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == CoreIdentMetrics.MeterName)
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            }
        };

        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags)
            {
                dict[tag.Key] = tag.Value;
            }
            measurements.Add(new Measurement(instrument.Name, measurement, dict));
        });

        listener.Start();

        return listener;
    }

    private async Task<string> IssueAccessTokenAsync(string clientId, string clientSecret)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["scope"] = "api"
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));

        var response = await Client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Token endpoint should return 200 OK.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Token response should deserialize.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");

        return tokenResponse.AccessToken;
    }

    private static async Task WaitForAsync(Func<bool> predicate, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();

        while (sw.Elapsed < timeout)
        {
            if (predicate())
            {
                return;
            }

            await Task.Delay(25);
        }

        predicate().ShouldBeTrue($"Condition not met within {timeout}.");
    }

    private sealed record Measurement(string Name, long Value, IReadOnlyDictionary<string, object?> Tags);
}
