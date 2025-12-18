using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace CoreIdent.Client;

/// <summary>
/// Stores tokens in an encrypted file using ASP.NET Core Data Protection.
/// </summary>
public sealed class FileTokenStorage : ISecureTokenStorage
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly string _filePath;
    private readonly IDataProtector _protector;

    /// <summary>
    /// Creates a new instance.
    /// </summary>
    /// <param name="filePath">Path to the token file.</param>
    /// <param name="dataProtectionProvider">Optional data protection provider.</param>
    /// <remarks>
    /// If <paramref name="dataProtectionProvider"/> is not provided, an ephemeral provider is created.
    /// Persisted keys are app-owned; for a stable token cache across process restarts you should provide a configured provider.
    /// </remarks>
    public FileTokenStorage(string filePath, IDataProtectionProvider? dataProtectionProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        _filePath = filePath;

        dataProtectionProvider ??= DataProtectionProvider.Create("CoreIdent.Client");
        _protector = dataProtectionProvider.CreateProtector("CoreIdent.Client.TokenSet");
    }

    /// <inheritdoc />
    public async Task StoreTokensAsync(TokenSet tokens, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        var dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var json = JsonSerializer.Serialize(tokens, SerializerOptions);
        var clearBytes = Encoding.UTF8.GetBytes(json);
        var protectedBytes = _protector.Protect(clearBytes);

        var tmp = _filePath + ".tmp";
        await File.WriteAllBytesAsync(tmp, protectedBytes, ct);

        File.Move(tmp, _filePath, overwrite: true);
    }

    /// <inheritdoc />
    public async Task<TokenSet?> GetTokensAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_filePath))
        {
            return null;
        }

        try
        {
            var protectedBytes = await File.ReadAllBytesAsync(_filePath, ct);
            var clearBytes = _protector.Unprotect(protectedBytes);
            var json = Encoding.UTF8.GetString(clearBytes);
            return JsonSerializer.Deserialize<TokenSet>(json, SerializerOptions);
        }
        catch
        {
            // If the file cannot be decrypted (e.g. key rotation), treat as not authenticated.
            return null;
        }
    }

    /// <inheritdoc />
    public Task ClearTokensAsync(CancellationToken ct = default)
    {
        if (File.Exists(_filePath))
        {
            File.Delete(_filePath);
        }

        return Task.CompletedTask;
    }
}
