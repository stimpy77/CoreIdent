using System.Text.Json.Serialization;

namespace CoreIdent.Core.Models;

public sealed record TokenIntrospectionRequest
{
    [JsonPropertyName("token")]
    public string Token { get; init; } = string.Empty;

    [JsonPropertyName("token_type_hint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenTypeHint { get; init; }
}
