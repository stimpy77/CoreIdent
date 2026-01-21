using CoreIdent.Client;
using CoreIdent.Client.Maui;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Maui.Tests;

public sealed class MauiSecureTokenStorageTests
{
    [Fact]
    public async Task Tokens_persist_across_instances()
    {
        var secureStorage = new FakeSecureStorageAdapter();
        var tokens = new TokenSet
        {
            AccessToken = "access",
            RefreshToken = "refresh",
            IdToken = "id",
            Scope = "openid profile",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1),
            TokenType = "Bearer"
        };

        var first = new MauiSecureTokenStorage(secureStorage, "coreident.tokens");
        await first.StoreTokensAsync(tokens);

        var second = new MauiSecureTokenStorage(secureStorage, "coreident.tokens");
        var restored = await second.GetTokensAsync();

        restored.ShouldNotBeNull("Tokens should be restored from secure storage.");
        restored!.AccessToken.ShouldBe(tokens.AccessToken, "Access token should persist across instances.");
        restored.RefreshToken.ShouldBe(tokens.RefreshToken, "Refresh token should persist across instances.");
        restored.IdToken.ShouldBe(tokens.IdToken, "ID token should persist across instances.");
        restored.Scope.ShouldBe(tokens.Scope, "Scopes should persist across instances.");
        restored.TokenType.ShouldBe(tokens.TokenType, "Token type should persist across instances.");
    }

    private sealed class FakeSecureStorageAdapter : IMauiSecureStorageAdapter
    {
        private readonly Dictionary<string, string> _storage = new(StringComparer.Ordinal);

        public Task SetAsync(string key, string value, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            _storage[key] = value;
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string key, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            _storage.TryGetValue(key, out var value);
            return Task.FromResult<string?>(value);
        }

        public bool Remove(string key)
        {
            return _storage.Remove(key);
        }
    }
}
