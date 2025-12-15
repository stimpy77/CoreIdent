namespace CoreIdent.Core.Configuration;

public sealed class SmtpOptions
{
    public string? Host { get; set; }

    public int Port { get; set; } = 587;

    public bool EnableTls { get; set; } = true;

    public string? UserName { get; set; }

    public string? Password { get; set; }

    public string? FromAddress { get; set; }

    public string? FromDisplayName { get; set; }
}
