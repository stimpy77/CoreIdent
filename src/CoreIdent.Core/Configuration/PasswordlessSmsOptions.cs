namespace CoreIdent.Core.Configuration;

public sealed class PasswordlessSmsOptions
{
    public TimeSpan OtpLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public int MaxAttemptsPerHour { get; set; } = 5;
}
