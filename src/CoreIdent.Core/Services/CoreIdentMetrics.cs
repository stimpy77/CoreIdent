using System.Diagnostics.Metrics;
using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Options;

using TagList = System.Diagnostics.TagList;

namespace CoreIdent.Core.Services;

/// <summary>
/// Default <see cref="ICoreIdentMetrics"/> implementation backed by <see cref="System.Diagnostics.Metrics"/>.
/// </summary>
public sealed class CoreIdentMetrics(IOptions<CoreIdentMetricsOptions> options) : ICoreIdentMetrics
{
    /// <summary>
    /// The meter name used by CoreIdent.
    /// </summary>
    public const string MeterName = "CoreIdent";

    // Static Meter is intentional: System.Diagnostics.Metrics expects a single Meter per logical
    // component so that all instruments are aggregated together by listeners. Creating a Meter
    // per DI instance would fragment metrics across multiple meter instances.
    private static readonly Meter Meter = new(MeterName, version: "1.0.0");

    private readonly CoreIdentMetricsOptions _options = options.Value;

    private static readonly Counter<long> TokenIssuedCounter = Meter.CreateCounter<long>(
        "coreident.token.issued",
        unit: "{token}",
        description: "Number of tokens issued");

    private static readonly Counter<long> TokenRevokedCounter = Meter.CreateCounter<long>(
        "coreident.token.revoked",
        unit: "{token}",
        description: "Number of tokens revoked");

    private static readonly Counter<long> ClientAuthenticatedCounter = Meter.CreateCounter<long>(
        "coreident.client.authenticated",
        unit: "{request}",
        description: "Number of client authentication attempts");

    private static readonly Histogram<double> TokenIssuanceDuration = Meter.CreateHistogram<double>(
        "coreident.token.issuance.duration",
        unit: "ms",
        description: "Duration of token issuance in milliseconds");

    private static readonly Histogram<double> ClientAuthenticationDuration = Meter.CreateHistogram<double>(
        "coreident.client.authentication.duration",
        unit: "ms",
        description: "Duration of client authentication in milliseconds");

    /// <inheritdoc />
    public void ClientAuthenticated(string clientType, bool success, double elapsedMilliseconds)
    {
        if (!ShouldRecord(new CoreIdentMetricContext("coreident.client.authenticated", ClientType: clientType, Success: success)))
        {
            return;
        }

        var tags = new TagList
        {
            { "client_type", clientType },
            { "success", success }
        };

        ClientAuthenticatedCounter.Add(1, tags);
        ClientAuthenticationDuration.Record(elapsedMilliseconds, tags);
    }

    /// <inheritdoc />
    public void TokenIssued(string tokenType, string grantType, double elapsedMilliseconds)
    {
        if (!ShouldRecord(new CoreIdentMetricContext("coreident.token.issued", TokenType: tokenType, GrantType: grantType)))
        {
            return;
        }

        var tags = new TagList
        {
            { "token_type", tokenType },
            { "grant_type", grantType }
        };

        TokenIssuedCounter.Add(1, tags);
        TokenIssuanceDuration.Record(elapsedMilliseconds, tags);
    }

    /// <inheritdoc />
    public void TokenRevoked(string tokenType)
    {
        if (!ShouldRecord(new CoreIdentMetricContext("coreident.token.revoked", TokenType: tokenType)))
        {
            return;
        }

        TokenRevokedCounter.Add(1, new KeyValuePair<string, object?>("token_type", tokenType));
    }

    private bool ShouldRecord(CoreIdentMetricContext context)
    {
        if (_options.SampleRate <= 0)
        {
            return false;
        }

        if (_options.SampleRate < 1.0 && Random.Shared.NextDouble() > _options.SampleRate)
        {
            return false;
        }

        return _options.Filter?.Invoke(context) ?? true;
    }
}
