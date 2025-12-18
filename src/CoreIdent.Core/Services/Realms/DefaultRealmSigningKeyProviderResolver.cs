using CoreIdent.Core.Services;

namespace CoreIdent.Core.Services.Realms;

/// <summary>
/// Default implementation that returns a single signing key provider for all realms.
/// </summary>
public sealed class DefaultRealmSigningKeyProviderResolver : IRealmSigningKeyProviderResolver
{
    private readonly ISigningKeyProvider _signingKeyProvider;

    /// <summary>
    /// Initializes a new instance of <see cref="DefaultRealmSigningKeyProviderResolver"/> class.
    /// </summary>
    /// <param name="signingKeyProvider">The signing key provider to use for all realms.</param>
    public DefaultRealmSigningKeyProviderResolver(ISigningKeyProvider signingKeyProvider)
    {
        _signingKeyProvider = signingKeyProvider ?? throw new ArgumentNullException(nameof(signingKeyProvider));
    }

    /// <inheritdoc />
    public Task<ISigningKeyProvider> GetSigningKeyProviderAsync(string realmId, CancellationToken ct = default)
    {
        return Task.FromResult(_signingKeyProvider);
    }
}
