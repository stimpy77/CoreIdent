namespace CoreIdent.Client;

/// <summary>
/// In-memory token storage (non-persistent).
/// </summary>
public sealed class InMemoryTokenStorage : ISecureTokenStorage
{
    private readonly object _gate = new();
    private TokenSet? _tokens;

    /// <inheritdoc />
    public Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        lock (_gate)
        {
            _tokens = tokens;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<TokenSet?> GetTokensAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_tokens);
        }
    }

    /// <inheritdoc />
    public Task ClearTokensAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            _tokens = null;
        }

        return Task.CompletedTask;
    }
}
