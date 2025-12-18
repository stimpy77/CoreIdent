using CoreIdent.Core.Extensions;
using Microsoft.Extensions.Logging;

namespace CoreIdent.Core.Services;

/// <summary>
/// SMS provider that writes messages to the console. Intended for development only.
/// </summary>
public sealed class ConsoleSmsProvider : ISmsProvider
{
    private readonly ILogger<ConsoleSmsProvider> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConsoleSmsProvider"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public ConsoleSmsProvider(ILogger<ConsoleSmsProvider> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Task SendAsync(string phoneNumber, string message, CancellationToken ct = default)
    {
        _logger.LogInformation("[CoreIdent SMS] Sending SMS to {Phone}", CoreIdentRedaction.MaskPhone(phoneNumber));
        return Task.CompletedTask;
    }
}
