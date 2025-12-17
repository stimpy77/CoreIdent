namespace CoreIdent.Core.Extensions;

public static class CoreIdentRedaction
{
    public static string MaskEmail(string? email)
    {
        var value = (email ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var at = value.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0 || at == value.Length - 1)
        {
            return MaskGeneric(value);
        }

        var local = value[..at];
        var domain = value[(at + 1)..];

        var maskedLocal = local.Length switch
        {
            1 => "*",
            2 => local[0] + "*",
            _ => local[0] + new string('*', local.Length - 2) + local[^1]
        };

        var dot = domain.LastIndexOf('.');
        if (dot <= 0 || dot == domain.Length - 1)
        {
            return maskedLocal + "@" + MaskGeneric(domain);
        }

        var domainName = domain[..dot];
        var tld = domain[dot..];

        var maskedDomain = domainName.Length switch
        {
            1 => "*",
            2 => domainName[0] + "*",
            _ => domainName[0] + new string('*', domainName.Length - 2) + domainName[^1]
        };

        return maskedLocal + "@" + maskedDomain + tld;
    }

    public static string MaskPhone(string? phone)
    {
        var value = (phone ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var digits = new string(value.Where(char.IsDigit).ToArray());
        if (digits.Length <= 4)
        {
            return new string('*', Math.Max(1, digits.Length));
        }

        var last4 = digits[^4..];
        return "***" + last4;
    }

    private static string MaskGeneric(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (value.Length <= 2)
        {
            return new string('*', value.Length);
        }

        return value[0] + new string('*', value.Length - 2) + value[^1];
    }
}
