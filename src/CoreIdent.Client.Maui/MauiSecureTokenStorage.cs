using System.Text.Json;
using CoreIdent.Client;

namespace CoreIdent.Client.Maui;

/// <summary>
/// Stores tokens using .NET MAUI secure storage.
/// </summary>
public sealed class MauiSecureTokenStorage : ISecureTokenStorage
{
    private const string DefaultStorageKey = "CoreIdent.Client.TokenSet";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IMauiSecureStorageAdapter _storage;
    private readonly string _storageKey;

    /// <summary>
    /// Creates a new instance with default secure storage.
    /// </summary>
    /// <param name="storageKey">Optional storage key override.</param>
    public MauiSecureTokenStorage(string? storageKey = null)
        : this(null, storageKey)
    {
    }

    /// <summary>
    /// Creates a new instance (internal for testing).
    /// </summary>
    /// <param name="storage">Optional secure storage adapter.</param>
    /// <param name="storageKey">Optional storage key override.</param>
    internal MauiSecureTokenStorage(IMauiSecureStorageAdapter? storage, string? storageKey)
    {
        _storage = storage ?? MauiSecureStorageAdapter.Default;
        _storageKey = string.IsNullOrWhiteSpace(storageKey) ? DefaultStorageKey : storageKey;
    }

    /// <inheritdoc />
    public async Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        ct.ThrowIfCancellationRequested();

        var json = JsonSerializer.Serialize(tokens, SerializerOptions);
        await _storage.SetAsync(_storageKey, json, ct);
    }

    /// <inheritdoc />
    public async Task<TokenSet?> GetTokensAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            var json = await _storage.GetAsync(_storageKey, ct);
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            return JsonSerializer.Deserialize<TokenSet>(json, SerializerOptions);
        }
        catch
        {
            return null;
        }
    }

    /// <inheritdoc />
    public Task ClearTokensAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        _storage.Remove(_storageKey);
        return Task.CompletedTask;
    }
}
