using CoreIdent.Core.Services;

namespace CoreIdent.Testing.Mocks;

public sealed class MockEmailSender : IEmailSender
{
    private readonly List<EmailMessage> _messages = [];

    public IReadOnlyList<EmailMessage> Messages => _messages;

    public EmailMessage? LastMessage => _messages.Count == 0 ? null : _messages[^1];

    public void Clear()
    {
        _messages.Clear();
    }

    public Task SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        _messages.Add(message);
        return Task.CompletedTask;
    }
}
