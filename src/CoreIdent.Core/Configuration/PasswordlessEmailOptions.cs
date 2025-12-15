namespace CoreIdent.Core.Configuration;

public class PasswordlessEmailOptions
{
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    public int MaxAttemptsPerHour { get; set; } = 5;

    public string EmailSubject { get; set; } = "Sign in to {AppName}";

    public string? EmailTemplatePath { get; set; }

    public string VerifyEndpointUrl { get; set; } = "passwordless/email/verify";

    public string? SuccessRedirectUrl { get; set; }
}
