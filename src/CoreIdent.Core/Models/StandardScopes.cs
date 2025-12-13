namespace CoreIdent.Core.Models;

public static class StandardScopes
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string Email = "email";
    public const string Address = "address";
    public const string Phone = "phone";
    public const string OfflineAccess = "offline_access";

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
