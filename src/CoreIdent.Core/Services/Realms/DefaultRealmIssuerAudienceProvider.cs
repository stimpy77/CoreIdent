using CoreIdent.Core.Configuration;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Default implementation that provides issuer and audience values from configuration.
/// </summary>
public sealed class DefaultRealmIssuerAudienceProvider : IRealmIssuerAudienceProvider
{
    private readonly IOptions<CoreIdentOptions> _options;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultRealmIssuerAudienceProvider"/> class.
    /// </summary>
    /// <param name="options">The CoreIdent configuration options.</param>
    public DefaultRealmIssuerAudienceProvider(IOptions<CoreIdentOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
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
