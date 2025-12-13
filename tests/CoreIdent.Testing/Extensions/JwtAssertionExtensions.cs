using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;

namespace CoreIdent.Testing.Extensions;

public static class JwtAssertionExtensions
{
    public static JsonWebToken ShouldBeValidJwt(this string token)
    {
        token.ShouldNotBeNullOrWhiteSpace("Token should not be null/empty.");

        var handler = new JsonWebTokenHandler();
        handler.CanReadToken(token).ShouldBeTrue("Token should be in a readable JWT format.");

        var jwt = handler.ReadJsonWebToken(token);
        jwt.ShouldNotBeNull("Token should parse to a JsonWebToken.");

        return jwt;
    }

    public static JsonWebToken ShouldHaveClaim(this JsonWebToken token, string type, string? value = null)
    {
        var claim = token.Claims.FirstOrDefault(c => c.Type == type);
        claim.ShouldNotBeNull($"Token should contain claim '{type}'.");

        if (value is not null)
        {
            claim.Value.ShouldBe(value, $"Claim '{type}' should equal '{value}'.");
        }

        return token;
    }

    public static JsonWebToken ShouldExpireAfter(this JsonWebToken token, TimeSpan duration)
    {
        token.ValidTo.ShouldBeGreaterThan(DateTime.UtcNow.Add(duration).Subtract(TimeSpan.FromSeconds(30)),
            $"Token should expire at least {duration} from now.");
        return token;
    }

    public static string ShouldBeBase64Url(this string value)
    {
        value.ShouldNotBeNullOrWhiteSpace("Expected a base64url value.");

        try
        {
            _ = Base64UrlEncoder.DecodeBytes(value);
        }
        catch (Exception ex)
        {
            throw new ShouldAssertException($"Expected base64url string but could not decode: {ex.Message}");
        }

        return value;
    }
}
