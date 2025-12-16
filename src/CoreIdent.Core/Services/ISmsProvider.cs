namespace CoreIdent.Core.Services;

public interface ISmsProvider
{
    Task SendAsync(string phoneNumber, string message, CancellationToken ct = default);
}
