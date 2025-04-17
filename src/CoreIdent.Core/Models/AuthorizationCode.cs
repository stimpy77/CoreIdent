using System;
using System.Collections.Generic;

namespace CoreIdent.Core.Models;

/// <summary>
/// Represents the details of a stored authorization code.
/// </summary>
public class AuthorizationCode
{
    /// <summary>
    /// The handle/value of the authorization code.
    /// This should be stored securely (e.g., hashed if replay detection is needed externally).
    /// </summary>
    public string CodeHandle { get; set; } = default!;

    /// <summary>
    /// The client ID that requested the code.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// The subject ID (user ID) the code was issued to.
    /// </summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>
    /// The redirect URI associated with the authorization request.
    /// </summary>
    public string RedirectUri { get; set; } = default!;

    /// <summary>
    /// The scopes granted for this code.
    /// </summary>
    public List<string> RequestedScopes { get; set; } = new List<string>();

    /// <summary>
    /// The nonce value provided in the original authorization request (for OIDC).
    /// </summary>
    public string? Nonce { get; set; }

    /// <summary>
    /// The PKCE code challenge.
    /// </summary>
    public string? CodeChallenge { get; set; }

    /// <summary>
    /// The PKCE code challenge method ('S256' or 'plain').
    /// </summary>
    public string? CodeChallengeMethod { get; set; }

    /// <summary>
    /// The time the code was created.
    /// </summary>
    public DateTime CreationTime { get; set; }

    /// <summary>
    /// The expiration time of the code.
    /// </summary>
    public DateTime ExpirationTime { get; set; }

    /// <summary>
    /// Flag indicating if the code has been consumed (optional, depends on store implementation).
    /// Primarily, RemoveAuthorizationCodeAsync handles consumption.
    /// </summary>
    // public bool IsConsumed { get; set; } = false;

    // Consider adding SessionId or similar if needed for back-channel logout coordination later.
} 