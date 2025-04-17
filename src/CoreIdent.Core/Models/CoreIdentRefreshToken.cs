using System;

namespace CoreIdent.Core.Models;

/// <summary>
/// Represents a refresh token issued to a client for a specific user.
/// </summary>
public class CoreIdentRefreshToken
{
    /// <summary>
    /// A unique handle for the refresh token.
    /// This property can store either:
    /// 1. The raw token handle value (legacy)
    /// 2. The hashed token handle (secure)
    /// The actual token value presented by the client should never be stored directly in production.
    /// </summary>
    /// <remarks>
    /// This property is being phased out in favor of HashedHandle for improved security.
    /// It is maintained for backward compatibility during the migration period.
    /// </remarks>
    public string Handle { get; set; } = default!;

    /// <summary>
    /// The one-way hashed value of the refresh token handle.
    /// This is the secure way to store tokens as it prevents raw token exposure in case of a database breach.
    /// </summary>
    /// <remarks>
    /// This property stores the result of applying a one-way hash to the raw token handle,
    /// typically using the TokenHasher.HashToken method which includes salting with the user ID and client ID.
    /// </remarks>
    public string? HashedHandle { get; set; }

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

    /// <summary>
    /// Unique identifier for the token family. All tokens in the same chain
    /// (original and its descendants from refresh operations) share the same family ID.
    /// Used for token theft detection and family-wide revocation.
    /// </summary>
    public string FamilyId { get; set; } = default!;

    /// <summary>
    /// The handle of the previous token in the chain that was exchanged for this token.
    /// Null for the original token in a family.
    /// Used to track the parent-child relationship in token rotation.
    /// </summary>
    public string? PreviousTokenId { get; set; }

    // Optional: Could add SessionId or other correlation properties if needed.
} 