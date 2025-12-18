using System.Text.Json.Serialization;

namespace CoreIdent.Core.Models;

/// <summary>
/// OAuth 2.0 token introspection response per RFC 7662.
/// </summary>
public sealed record TokenIntrospectionResponse
{
    /// <summary>
    /// Whether the token is currently active.
    /// </summary>
    [JsonPropertyName("active")]
    public bool Active { get; init; }

    /// <summary>
    /// The token scope (space-delimited).
    /// </summary>
    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; init; }

    /// <summary>
    /// The client identifier.
    /// </summary>
    [JsonPropertyName("client_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientId { get; init; }

    /// <summary>
    /// The username of the token subject.
    /// </summary>
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; init; }

    /// <summary>
    /// The token type.
    /// </summary>
    [JsonPropertyName("token_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenType { get; init; }

    /// <summary>
    /// Token expiry time (seconds since Unix epoch).
    /// </summary>
    [JsonPropertyName("exp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Exp { get; init; }

    /// <summary>
    /// Token issued-at time (seconds since Unix epoch).
    /// </summary>
    [JsonPropertyName("iat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Iat { get; init; }

    /// <summary>
    /// The subject identifier.
    /// </summary>
    [JsonPropertyName("sub")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Sub { get; init; }

    /// <summary>
    /// The token audience.
    /// </summary>
    [JsonPropertyName("aud")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Aud { get; init; }

    /// <summary>
    /// The token issuer.
    /// </summary>
    [JsonPropertyName("iss")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Iss { get; init; }

    /// <summary>
    /// The token identifier (JTI).
    /// </summary>
    [JsonPropertyName("jti")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Jti { get; init; }
}
