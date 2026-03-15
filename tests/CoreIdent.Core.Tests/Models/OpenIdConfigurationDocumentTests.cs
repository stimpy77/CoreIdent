using CoreIdent.Core.Models;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Models;

public class OpenIdConfigurationDocumentTests
{
    private static readonly IReadOnlyList<string> GrantTypes = ["authorization_code", "client_credentials"];
    private static readonly IReadOnlyList<string> Scopes = ["openid", "profile"];
    private static readonly IReadOnlyList<string> Algorithms = ["RS256"];

    [Fact]
    public void Ctor_8param_sets_required_fields_and_nulls_optional()
    {
        var doc = new OpenIdConfigurationDocument(
            Issuer: "https://issuer.example.com",
            JwksUri: "https://issuer.example.com/.well-known/jwks.json",
            TokenEndpoint: "https://issuer.example.com/token",
            RevocationEndpoint: "https://issuer.example.com/revoke",
            IntrospectionEndpoint: "https://issuer.example.com/introspect",
            GrantTypesSupported: GrantTypes,
            ScopesSupported: Scopes,
            IdTokenSigningAlgValuesSupported: Algorithms);

        doc.Issuer.ShouldBe("https://issuer.example.com", "Issuer should be set.");
        doc.JwksUri.ShouldBe("https://issuer.example.com/.well-known/jwks.json", "JwksUri should be set.");
        doc.TokenEndpoint.ShouldBe("https://issuer.example.com/token", "TokenEndpoint should be set.");
        doc.RevocationEndpoint.ShouldBe("https://issuer.example.com/revoke", "RevocationEndpoint should be set.");
        doc.IntrospectionEndpoint.ShouldBe("https://issuer.example.com/introspect", "IntrospectionEndpoint should be set.");
        doc.GrantTypesSupported.ShouldBe(GrantTypes, "GrantTypesSupported should be set.");
        doc.ScopesSupported.ShouldBe(Scopes, "ScopesSupported should be set.");
        doc.IdTokenSigningAlgValuesSupported.ShouldBe(Algorithms, "IdTokenSigningAlgValuesSupported should be set.");
        doc.ResponseTypesSupported.ShouldBeNull("ResponseTypesSupported should default to null.");
        doc.TokenEndpointAuthMethodsSupported.ShouldBeNull("TokenEndpointAuthMethodsSupported should default to null.");
        doc.AuthorizationEndpoint.ShouldBeNull("AuthorizationEndpoint should default to null.");
        doc.UserInfoEndpoint.ShouldBeNull("UserInfoEndpoint should default to null.");
    }

    [Fact]
    public void Ctor_10param_sets_response_types_and_auth_methods()
    {
        var responseTypes = new List<string> { "code" };
        var authMethods = new List<string> { "client_secret_basic", "client_secret_post" };

        var doc = new OpenIdConfigurationDocument(
            Issuer: "https://issuer.example.com",
            JwksUri: "https://issuer.example.com/.well-known/jwks.json",
            TokenEndpoint: "https://issuer.example.com/token",
            RevocationEndpoint: "https://issuer.example.com/revoke",
            IntrospectionEndpoint: "https://issuer.example.com/introspect",
            GrantTypesSupported: GrantTypes,
            ScopesSupported: Scopes,
            IdTokenSigningAlgValuesSupported: Algorithms,
            ResponseTypesSupported: responseTypes,
            TokenEndpointAuthMethodsSupported: authMethods);

        doc.ResponseTypesSupported.ShouldBe(responseTypes, "ResponseTypesSupported should be set.");
        doc.TokenEndpointAuthMethodsSupported.ShouldBe(authMethods, "TokenEndpointAuthMethodsSupported should be set.");
        doc.AuthorizationEndpoint.ShouldBeNull("AuthorizationEndpoint should default to null.");
        doc.UserInfoEndpoint.ShouldBeNull("UserInfoEndpoint should default to null.");
    }

    [Fact]
    public void Ctor_12param_sets_all_fields()
    {
        var doc = new OpenIdConfigurationDocument(
            Issuer: "https://issuer.example.com",
            JwksUri: "https://issuer.example.com/.well-known/jwks.json",
            TokenEndpoint: "https://issuer.example.com/token",
            RevocationEndpoint: "https://issuer.example.com/revoke",
            IntrospectionEndpoint: "https://issuer.example.com/introspect",
            GrantTypesSupported: GrantTypes,
            ScopesSupported: Scopes,
            IdTokenSigningAlgValuesSupported: Algorithms,
            ResponseTypesSupported: ["code"],
            TokenEndpointAuthMethodsSupported: ["client_secret_basic"],
            AuthorizationEndpoint: "https://issuer.example.com/authorize",
            UserInfoEndpoint: "https://issuer.example.com/userinfo");

        doc.AuthorizationEndpoint.ShouldBe("https://issuer.example.com/authorize", "AuthorizationEndpoint should be set.");
        doc.UserInfoEndpoint.ShouldBe("https://issuer.example.com/userinfo", "UserInfoEndpoint should be set.");
    }
}
