namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentMetricsOptions
{
    public double SampleRate { get; set; } = 1.0;

    public Func<CoreIdentMetricContext, bool>? Filter { get; set; }
}

public sealed record CoreIdentMetricContext(string MetricName, string? TokenType = null, string? GrantType = null, string? ClientType = null, bool? Success = null);
