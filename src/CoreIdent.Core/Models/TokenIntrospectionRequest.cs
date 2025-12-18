using System.Text.Json.Serialization;

namespace CoreIdent.Core.Models;

/// <summary>
/// OAuth 2.0 token introspection request per RFC 7662.
/// </summary>
public sealed record TokenIntrospectionRequest
{
    /// <summary>
    /// The token to introspect.
    /// </summary>
    [JsonPropertyName("token")]
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// Optional token type hint.
    /// </summary>
    [JsonPropertyName("token_type_hint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenTypeHint { get; init; }
}
