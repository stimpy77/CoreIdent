namespace CoreIdent.Client;

/// <summary>
/// OAuth 2.0 / OIDC protocol constants used by the client library.
/// Intentionally separate from CoreIdent.Core constants — the client library is standalone.
/// </summary>
internal static class OAuthClientConstants
{
    /// <summary>OAuth form/query parameter names.</summary>
    internal static class Parameters
    {
        internal const string ClientId = "client_id";
        internal const string RedirectUri = "redirect_uri";
        internal const string ResponseType = "response_type";
        internal const string Scope = "scope";
        internal const string State = "state";
        internal const string Nonce = "nonce";
        internal const string CodeChallenge = "code_challenge";
        internal const string CodeChallengeMethod = "code_challenge_method";
        internal const string GrantType = "grant_type";
        internal const string Code = "code";
        internal const string CodeVerifier = "code_verifier";
        internal const string Token = "token";
        internal const string TokenTypeHint = "token_type_hint";
        internal const string IdTokenHint = "id_token_hint";
        internal const string PostLogoutRedirectUri = "post_logout_redirect_uri";
        internal const string RefreshToken = "refresh_token";
    }

    /// <summary>OAuth grant type values.</summary>
    internal static class GrantTypes
    {
        internal const string AuthorizationCode = "authorization_code";
        internal const string RefreshToken = "refresh_token";
    }

    /// <summary>Common OAuth protocol values.</summary>
    internal static class Values
    {
        internal const string S256 = "S256";
        internal const string Code = "code";
        internal const string Bearer = "Bearer";
    }

    /// <summary>DPoP-related constants.</summary>
    internal static class DPoP
    {
        internal const string Typ = "dpop+jwt";
        internal const string Jwk = "jwk";
        internal const string UseDpopNonce = "use_dpop_nonce";
    }

    /// <summary>JWK parameter names.</summary>
    internal static class JwkParams
    {
        internal const string Kty = "kty";
        internal const string Crv = "crv";
        internal const string X = "x";
        internal const string Y = "y";
        internal const string EC = "EC";
        internal const string P256 = "P-256";
    }
}
