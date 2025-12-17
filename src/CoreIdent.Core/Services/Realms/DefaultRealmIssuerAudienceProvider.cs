using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services.Realms;

public sealed class DefaultRealmIssuerAudienceProvider : IRealmIssuerAudienceProvider
{
    private readonly IOptions<CoreIdentOptions> _options;

    public DefaultRealmIssuerAudienceProvider(IOptions<CoreIdentOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public Task<(string Issuer, string Audience)> GetIssuerAndAudienceAsync(string realmId, CancellationToken ct = default)
    {
        var value = _options.Value;

        if (string.IsNullOrWhiteSpace(value.Issuer))
        {
            throw new InvalidOperationException($"{nameof(CoreIdentOptions.Issuer)} must be configured.");
        }

        if (string.IsNullOrWhiteSpace(value.Audience))
        {
            throw new InvalidOperationException($"{nameof(CoreIdentOptions.Audience)} must be configured.");
        }

        return Task.FromResult((value.Issuer, value.Audience));
    }
}
