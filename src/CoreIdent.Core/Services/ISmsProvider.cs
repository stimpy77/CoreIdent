namespace CoreIdent.Core.Services;

/// <summary>
/// Sends SMS messages.
/// </summary>
public interface ISmsProvider
{
    /// <summary>
    /// Sends an SMS message.
    /// </summary>
    /// <param name="phoneNumber">The recipient phone number.</param>
    /// <param name="message">The message body.</param>
    /// <param name="ct">The cancellation token.</param>
    Task SendAsync(string phoneNumber, string message, CancellationToken ct = default);
}
