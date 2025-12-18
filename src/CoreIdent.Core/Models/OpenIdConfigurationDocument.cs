using System.Text.Json.Serialization;

namespace CoreIdent.Core.Models;

/// <summary>
/// OpenID Connect discovery document response.
/// </summary>
public sealed record OpenIdConfigurationDocument
{
    /// <summary>
    /// Creates a new <see cref="OpenIdConfigurationDocument"/>.
    /// </summary>
    /// <param name="issuer">Issuer identifier.</param>
    /// <param name="jwksUri">JWKS endpoint URI.</param>
    /// <param name="tokenEndpoint">Token endpoint URI.</param>
    /// <param name="revocationEndpoint">Token revocation endpoint URI.</param>
    /// <param name="introspectionEndpoint">Token introspection endpoint URI.</param>
    /// <param name="grantTypesSupported">Supported grant types.</param>
    /// <param name="scopesSupported">Supported scopes.</param>
    /// <param name="idTokenSigningAlgValuesSupported">Supported ID token signing algorithms.</param>
    public OpenIdConfigurationDocument(
        string Issuer,
        string JwksUri,
        string TokenEndpoint,
        string RevocationEndpoint,
        string IntrospectionEndpoint,
        IReadOnlyList<string> GrantTypesSupported,
        IReadOnlyList<string> ScopesSupported,
        IReadOnlyList<string> IdTokenSigningAlgValuesSupported)
    {
        this.Issuer = Issuer;
        this.JwksUri = JwksUri;
        this.TokenEndpoint = TokenEndpoint;
        this.RevocationEndpoint = RevocationEndpoint;
        this.IntrospectionEndpoint = IntrospectionEndpoint;
        this.GrantTypesSupported = GrantTypesSupported;
        this.ScopesSupported = ScopesSupported;
        this.IdTokenSigningAlgValuesSupported = IdTokenSigningAlgValuesSupported;
    }

    /// <summary>
    /// Issuer identifier.
    /// </summary>
    [JsonPropertyName("issuer")]
    public string Issuer { get; init; }

    /// <summary>
    /// JWKS endpoint URI.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; init; }

    /// <summary>
    /// Token endpoint URI.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; init; }

    /// <summary>
    /// Token revocation endpoint URI.
    /// </summary>
    [JsonPropertyName("revocation_endpoint")]
    public string RevocationEndpoint { get; init; }

    /// <summary>
    /// Token introspection endpoint URI.
    /// </summary>
    [JsonPropertyName("introspection_endpoint")]
    public string IntrospectionEndpoint { get; init; }

    /// <summary>
    /// Supported grant types.
    /// </summary>
    [JsonPropertyName("grant_types_supported")]
    public IReadOnlyList<string> GrantTypesSupported { get; init; }

    /// <summary>
    /// Supported scopes.
    /// </summary>
    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string> ScopesSupported { get; init; }

    /// <summary>
    /// Supported ID token signing algorithms.
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }
}
