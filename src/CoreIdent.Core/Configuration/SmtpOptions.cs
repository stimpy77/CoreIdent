namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options for SMTP email delivery.
/// </summary>
public sealed class SmtpOptions
{
    /// <summary>
    /// SMTP host.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    /// SMTP port.
    /// </summary>
    public int Port { get; set; } = 587;

    /// <summary>
    /// Whether to enable TLS.
    /// </summary>
    public bool EnableTls { get; set; } = true;

    /// <summary>
    /// Optional SMTP username.
    /// </summary>
    public string? UserName { get; set; }

    /// <summary>
    /// Optional SMTP password.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Sender email address.
    /// </summary>
    public string? FromAddress { get; set; }

    /// <summary>
    /// Optional sender display name.
    /// </summary>
    public string? FromDisplayName { get; set; }
}
