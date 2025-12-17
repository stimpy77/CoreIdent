using System.Security.Claims;
using CoreIdent.Core.Services;
using CoreIdent.Core.Services.Realms;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class JwtTokenServiceTests
{
    [Fact]
    public async Task CreateJwtAsync_creates_token_that_validates_with_provider_keys()
    {
        var keyProvider = new RsaSigningKeyProvider(
            Microsoft.Extensions.Options.Options.Create(new CoreIdent.Core.Configuration.CoreIdentKeyOptions { RsaKeySize = 2048 }),
            NullLogger<RsaSigningKeyProvider>.Instance);

        var realmContext = new TestRealmContext("default");
        var resolver = new TestRealmSigningKeyProviderResolver(keyProvider);

        var tokenService = new JwtTokenService(realmContext, resolver, NullLogger<JwtTokenService>.Instance);

        var token = await tokenService.CreateJwtAsync(
            issuer: "test-issuer",
            audience: "test-audience",
            claims: new[] { new Claim("sub", "user1") },
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(5));

        token.ShouldNotBeNullOrWhiteSpace("JWT should be created.");

        var signingCredentials = await keyProvider.GetSigningCredentialsAsync();
        var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token);
        parsed.Header.Kid.ShouldBe(signingCredentials.Key.KeyId, "JWT header kid should match signing key provider kid.");

        var handler = new JsonWebTokenHandler();
        var validationKeys = await keyProvider.GetValidationKeysAsync();

        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "test-issuer",
            ValidAudience = "test-audience",
            IssuerSigningKeys = validationKeys.Select(k => k.Key)
        });

        result.IsValid.ShouldBeTrue("Token should validate against provider validation keys.");
    }

    private sealed class TestRealmContext : ICoreIdentRealmContext
    {
        public TestRealmContext(string realmId)
        {
            RealmId = realmId;
        }

        public string RealmId { get; }
    }

    private sealed class TestRealmSigningKeyProviderResolver : IRealmSigningKeyProviderResolver
    {
        private readonly ISigningKeyProvider _provider;

        public TestRealmSigningKeyProviderResolver(ISigningKeyProvider provider)
        {
            _provider = provider;
        }

        public Task<ISigningKeyProvider> GetSigningKeyProviderAsync(string realmId, CancellationToken ct = default)
        {
            return Task.FromResult(_provider);
        }
    }
}
