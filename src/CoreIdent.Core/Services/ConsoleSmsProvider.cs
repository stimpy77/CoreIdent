namespace CoreIdent.Core.Services;

/// <summary>
/// SMS provider that writes messages to the console. Intended for development only.
/// </summary>
public sealed class ConsoleSmsProvider : ISmsProvider
{
    /// <inheritdoc />
    public Task SendAsync(string phoneNumber, string message, CancellationToken ct = default)
    {
        Console.WriteLine($"[CoreIdent SMS] To={phoneNumber} Message={message}");
        return Task.CompletedTask;
    }
}
