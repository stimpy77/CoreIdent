namespace CoreIdent.Client;

/// <summary>
/// Result returned by login operations.
/// </summary>
public sealed record AuthResult
{
    /// <summary>
    /// Whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// Optional error code.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Optional error description.
    /// </summary>
    public string? ErrorDescription { get; init; }

    /// <summary>
    /// Creates a success result.
    /// </summary>
    public static AuthResult Success() => new() { IsSuccess = true };

    /// <summary>
    /// Creates a failure result.
    /// </summary>
    public static AuthResult Fail(string error, string? description = null) => new()
    {
        IsSuccess = false,
        Error = error,
        ErrorDescription = description
    };
}
