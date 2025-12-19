using System.Security.Cryptography;
using System.Text;

namespace CoreIdent.Client;

/// <summary>
/// Helpers for PKCE (RFC 7636).
/// </summary>
public static class Pkce
{
    /// <summary>
    /// Creates a code verifier.
    /// </summary>
    public static string CreateCodeVerifier(int sizeBytes = 32)
    {
        if (sizeBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        }

        var bytes = RandomNumberGenerator.GetBytes(sizeBytes);
        return Base64UrlEncode(bytes);
    }

    /// <summary>
    /// Creates a code challenge for S256.
    /// </summary>
    public static string CreateS256CodeChallenge(string codeVerifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier);

        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hashed = SHA256.HashData(bytes);
        return Base64UrlEncode(hashed);
    }

    internal static string Base64UrlEncode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        s = s.TrimEnd('=');
        s = s.Replace('+', '-').Replace('/', '_');
        return s;
    }
}
