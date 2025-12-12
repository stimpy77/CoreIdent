using CoreIdent.Core.Configuration;
using CoreIdent.Core.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Services;

public class SymmetricSigningKeyProviderTests
{
    [Fact]
    public async Task GetSigningCredentialsAsync_uses_HS256()
    {
        var options = Options.Create(new CoreIdentKeyOptions
        {
            Type = KeyType.Symmetric,
            SymmetricKey = new string('a', 32)
        });

        var provider = new SymmetricSigningKeyProvider(options, NullLogger<SymmetricSigningKeyProvider>.Instance);

        var creds = await provider.GetSigningCredentialsAsync();

        creds.Algorithm.ShouldBe(SecurityAlgorithms.HmacSha256, "Algorithm should be HS256.");
        creds.Key.ShouldBeOfType<SymmetricSecurityKey>("Key should be symmetric.");
    }

    [Fact]
    public async Task GetSigningCredentialsAsync_requires_key_length()
    {
        var options = Options.Create(new CoreIdentKeyOptions
        {
            Type = KeyType.Symmetric,
            SymmetricKey = "short"
        });

        var provider = new SymmetricSigningKeyProvider(options, NullLogger<SymmetricSigningKeyProvider>.Instance);

        await Should.ThrowAsync<InvalidOperationException>(
            async () => await provider.GetSigningCredentialsAsync(),
            "Should throw when SymmetricKey is too short.");
    }
}
