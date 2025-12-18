using CoreIdent.Client;
using Shouldly;
using Xunit;

namespace CoreIdent.Client.Tests;

public sealed class PkceTests
{
    [Fact]
    public void CreateS256CodeChallenge_matches_rfc7636_example()
    {
        // RFC 7636, section 4.2
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        var challenge = Pkce.CreateS256CodeChallenge(verifier);

        challenge.ShouldBe(expectedChallenge, "PKCE S256 challenge must match RFC 7636 example.");
    }

    [Fact]
    public void CreateCodeVerifier_is_url_safe_and_has_no_padding()
    {
        var verifier = Pkce.CreateCodeVerifier();

        verifier.ShouldNotBeNullOrWhiteSpace("Code verifier should not be empty.");
        verifier.Contains('=').ShouldBeFalse("Code verifier should be base64url without padding.");
        verifier.Contains('+').ShouldBeFalse("Code verifier should be base64url encoded.");
        verifier.Contains('/').ShouldBeFalse("Code verifier should be base64url encoded.");
    }
}
