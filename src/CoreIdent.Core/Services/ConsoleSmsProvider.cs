namespace CoreIdent.Core.Services;

public sealed class ConsoleSmsProvider : ISmsProvider
{
    public Task SendAsync(string phoneNumber, string message, CancellationToken ct = default)
    {
        Console.WriteLine($"[CoreIdent SMS] To={phoneNumber} Message={message}");
        return Task.CompletedTask;
    }
}
