namespace CoreIdent.Core.Models;

/// <summary>
/// Standard OpenID Connect scope names.
/// </summary>
public static class StandardScopes
{
    /// <summary>
    /// The <c>openid</c> scope.
    /// </summary>
    public const string OpenId = "openid";

    /// <summary>
    /// The <c>profile</c> scope.
    /// </summary>
    public const string Profile = "profile";

    /// <summary>
    /// The <c>email</c> scope.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// The <c>address</c> scope.
    /// </summary>
    public const string Address = "address";

    /// <summary>
    /// The <c>phone</c> scope.
    /// </summary>
    public const string Phone = "phone";

    /// <summary>
    /// The <c>offline_access</c> scope.
    /// </summary>
    public const string OfflineAccess = "offline_access";

    /// <summary>
    /// All standard scope names.
    /// </summary>
    public static readonly IReadOnlyList<string> All =
    [
        OpenId,
        Profile,
        Email,
        Address,
        Phone,
        OfflineAccess
    ];
}
