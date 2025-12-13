using CoreIdent.Core.Models;

namespace CoreIdent.Testing.Seeders;

public static class StandardClients
{
    public const string PublicClientId = "test-public-client";

    public const string ConfidentialClientId = "test-confidential-client";

    public const string ConfidentialClientSecret = "test-secret";

    public static CoreIdentClient CreatePublicClient() => new()
    {
        ClientId = PublicClientId,
        ClientName = "Test Public Client",
        ClientType = ClientType.Public,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        AllowedScopes = [CoreIdent.Core.Models.StandardScopes.OpenId, CoreIdent.Core.Models.StandardScopes.Profile],
        RequirePkce = true,
        Enabled = true,
        CreatedAt = DateTime.UtcNow
    };

    public static CoreIdentClient CreateConfidentialClient(string clientSecretHash) => new()
    {
        ClientId = ConfidentialClientId,
        ClientSecretHash = clientSecretHash,
        ClientName = "Test Confidential Client",
        ClientType = ClientType.Confidential,
        AllowedGrantTypes = [GrantTypes.ClientCredentials, GrantTypes.RefreshToken],
        AllowedScopes = [CoreIdent.Core.Models.StandardScopes.OpenId, CoreIdent.Core.Models.StandardScopes.Profile],
        AllowOfflineAccess = true,
        RequirePkce = false,
        Enabled = true,
        CreatedAt = DateTime.UtcNow
    };
}
