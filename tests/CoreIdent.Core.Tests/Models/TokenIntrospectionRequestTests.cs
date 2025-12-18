using System.Text.Json;
using CoreIdent.Core.Models;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Models;

public sealed class TokenIntrospectionRequestTests
{
    [Fact]
    public void Token_defaults_to_empty_string()
    {
        var request = new TokenIntrospectionRequest();

        request.Token.ShouldBe(string.Empty);
        request.TokenTypeHint.ShouldBeNull();
    }

    [Fact]
    public void Serializes_with_expected_property_names_and_omits_token_type_hint_when_null()
    {
        var request = new TokenIntrospectionRequest
        {
            Token = "abc",
            TokenTypeHint = null
        };

        var json = JsonSerializer.Serialize(request);

        json.ShouldContain("\"token\":\"abc\"");
        json.ShouldNotContain("token_type_hint");
    }

    [Fact]
    public void Serializes_token_type_hint_when_provided()
    {
        var request = new TokenIntrospectionRequest
        {
            Token = "abc",
            TokenTypeHint = "access_token"
        };

        var json = JsonSerializer.Serialize(request);

        json.ShouldContain("\"token\":\"abc\"");
        json.ShouldContain("\"token_type_hint\":\"access_token\"");
    }
}
