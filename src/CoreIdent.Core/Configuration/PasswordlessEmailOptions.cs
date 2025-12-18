namespace CoreIdent.Core.Configuration;

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
}
