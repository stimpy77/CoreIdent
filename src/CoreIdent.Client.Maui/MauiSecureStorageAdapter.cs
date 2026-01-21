#if ANDROID || IOS || MACCATALYST
using Microsoft.Maui.Storage;
#endif

namespace CoreIdent.Client.Maui;

/// <summary>
/// Abstraction over MAUI SecureStorage for testability.
/// </summary>
internal interface IMauiSecureStorageAdapter
{
    Task SetAsync(string key, string value, CancellationToken ct = default);
    Task<string?> GetAsync(string key, CancellationToken ct = default);
    bool Remove(string key);
}

#if ANDROID || IOS || MACCATALYST
internal sealed class MauiSecureStorageAdapter : IMauiSecureStorageAdapter
{
    public static MauiSecureStorageAdapter Default { get; } = new();

    public Task SetAsync(string key, string value, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return SecureStorage.Default.SetAsync(key, value);
    }

    public Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return SecureStorage.Default.GetAsync(key);
    }

    public bool Remove(string key)
    {
        return SecureStorage.Default.Remove(key);
    }
}
#else
// Stub for net10.0 (unit test) builds - real implementation only on MAUI platforms
internal sealed class MauiSecureStorageAdapter : IMauiSecureStorageAdapter
{
    public static MauiSecureStorageAdapter Default { get; } = new();

    public Task SetAsync(string key, string value, CancellationToken ct = default)
    {
        throw new PlatformNotSupportedException("SecureStorage is only available on MAUI platforms.");
    }

    public Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        throw new PlatformNotSupportedException("SecureStorage is only available on MAUI platforms.");
    }

    public bool Remove(string key)
    {
        throw new PlatformNotSupportedException("SecureStorage is only available on MAUI platforms.");
    }
}
#endif
