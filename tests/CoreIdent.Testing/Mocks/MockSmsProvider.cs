using CoreIdent.Core.Services;

namespace CoreIdent.Testing.Mocks;

public sealed class MockSmsProvider : ISmsProvider
{
    public sealed record SentSms(string PhoneNumber, string Message);

    private readonly List<SentSms> _messages = [];

    public IReadOnlyList<SentSms> Messages => _messages;

    public SentSms? LastMessage => _messages.Count == 0 ? null : _messages[^1];

    public void Clear()
    {
        _messages.Clear();
    }

    public Task SendAsync(string phoneNumber, string message, CancellationToken ct = default)
    {
        _messages.Add(new SentSms(phoneNumber, message));
        return Task.CompletedTask;
    }
}
