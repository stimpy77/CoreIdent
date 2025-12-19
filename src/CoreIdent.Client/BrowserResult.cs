namespace CoreIdent.Client;

/// <summary>
/// Result of launching an external browser.
/// </summary>
public sealed record BrowserResult
{
    /// <summary>
    /// Whether the browser flow succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// The final redirect URL (typically the redirect URI with query parameters).
    /// </summary>
    public string? ResponseUrl { get; init; }

    /// <summary>
    /// OAuth/OIDC error code.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// OAuth/OIDC error description.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Creates a success result.
    /// </summary>
    public static BrowserResult Success(string responseUrl) => new()
    {
        IsSuccess = true,
        ResponseUrl = responseUrl
    };

    /// <summary>
    /// Creates an error result.
    /// </summary>
    public static BrowserResult Fail(string error, string? description = null) => new()
    {
        IsSuccess = false,
        Error = error,
        ErrorDescription = description
    };
}
