using System;

namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a refresh token issued to a client for a specific user.
/// </summary>
public class CoreIdentRefreshToken
{
    /// <summary>
    /// A unique handle for the refresh token.
    /// Note: This handle should be stored securely (e.g., hashed) in the database.
    /// The actual token value presented by the client is derived from or related to this handle.
    /// </summary>
    public string Handle { get; set; } = default!;

    /// <summary>
    /// The subject identifier (user ID) this token was issued to.
    /// </summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>
    /// The client identifier this token was issued for.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// The UTC time this token was created.
    /// </summary>
    public DateTime CreationTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The UTC time this token expires.
    /// </summary>
    public DateTime ExpirationTime { get; set; }

    /// <summary>
    /// The UTC time this token was consumed (used). Null if not consumed.
    /// Used for detecting replay attacks with token rotation.
    /// </summary>
    public DateTime? ConsumedTime { get; set; }

    // Optional: Could add SessionId or other correlation properties if needed.
} 