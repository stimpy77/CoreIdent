namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options that control CoreIdent metrics emission.
/// </summary>
public sealed class CoreIdentMetricsOptions
{
    /// <summary>
    /// Sampling rate in the range [0, 1].
    /// </summary>
    public double SampleRate { get; set; } = 1.0;

    /// <summary>
    /// Optional filter that can suppress metrics based on context.
    /// </summary>
    public Func<CoreIdentMetricContext, bool>? Filter { get; set; }
}

/// <summary>
/// Provides context for filtering metric events.
/// </summary>
/// <param name="MetricName">Metric name.</param>
/// <param name="TokenType">Optional token type label.</param>
/// <param name="GrantType">Optional grant type label.</param>
/// <param name="ClientType">Optional client type label.</param>
/// <param name="Success">Optional success flag.</param>
public sealed record CoreIdentMetricContext(string MetricName, string? TokenType = null, string? GrantType = null, string? ClientType = null, bool? Success = null);
