namespace CoreIdent.Core.Configuration;

/// <summary>
/// Controls how tokens are delivered in the email verify redirect URL.
/// This is a token delivery mechanism, not an OAuth grant type.
/// </summary>
public enum TokenDeliveryMode
{
    /// <summary>
    /// Tokens appended as query string parameters (?access_token=...).
    /// Simplest; tokens may appear in server logs and Referer headers.
    /// </summary>
    QueryString,

    /// <summary>
    /// Tokens appended as fragment parameters (#access_token=...).
    /// More secure: fragments are never sent to the server, but require client-side JS to extract.
    /// </summary>
    Fragment,

    /// <summary>
    /// Server issues a short-lived authorization code that the client exchanges for tokens.
    /// Recommended for production. Planned — see DEVPLAN.md.
    /// </summary>
    AuthorizationCode
}

/// <summary>
/// Options for passwordless email authentication.
/// </summary>
public class PasswordlessEmailOptions
{
    /// <summary>
    /// Lifetime for issued email tokens.
    /// </summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Maximum allowed verification attempts per recipient per hour.
    /// </summary>
    public int MaxAttemptsPerHour { get; set; } = 5;

    /// <summary>
    /// Email subject template.
    /// </summary>
    public string EmailSubject { get; set; } = "Sign in to {AppName}";

    /// <summary>
    /// Optional path to an HTML email template.
    /// </summary>
    public string? EmailTemplatePath { get; set; }

    /// <summary>
    /// Verification endpoint URL or path used to construct magic links.
    /// </summary>
    public string VerifyEndpointUrl { get; set; } = "passwordless/email/verify";

    /// <summary>
    /// Optional URL to redirect to after successful verification.
    /// </summary>
    public string? SuccessRedirectUrl { get; set; }

    /// <summary>
    /// Maximum failed verify attempts before the token is burned.
    /// Email tokens are high-entropy so this is a defense-in-depth measure.
    /// </summary>
    public int MaxVerifyAttempts { get; set; } = 5;

    /// <summary>
    /// Controls how tokens are delivered in the verify redirect URL.
    /// Default is <see cref="TokenDeliveryMode.QueryString"/> for backwards compatibility.
    /// </summary>
    public TokenDeliveryMode TokenDelivery { get; set; } = TokenDeliveryMode.QueryString;
}
