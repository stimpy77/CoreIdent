using System.Text.Json.Serialization;

namespace CoreIdent.Client;

internal sealed record DiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; init; } = string.Empty;

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; init; }

    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; init; }

    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }
}
