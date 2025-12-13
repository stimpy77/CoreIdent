using CoreIdent.Core.Models;

namespace CoreIdent.Testing.Builders;

public sealed class ClientBuilder
{
    private string _clientId = $"client-{Guid.NewGuid():N}";
    private string _clientName = "Test Client";
    private ClientType _clientType = ClientType.Confidential;
    private bool _requirePkce;
    private bool _allowOfflineAccess;

    private readonly List<string> _allowedGrantTypes = [GrantTypes.ClientCredentials];
    private readonly List<string> _allowedScopes = [StandardScopes.OpenId, StandardScopes.Profile];

    public string? Secret { get; private set; }

    public ClientBuilder WithClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    public ClientBuilder WithClientName(string clientName)
    {
        _clientName = clientName;
        return this;
    }

    public ClientBuilder WithSecret(string secret)
    {
        Secret = secret;
        _clientType = ClientType.Confidential;
        return this;
    }

    public ClientBuilder WithGrantTypes(params string[] grantTypes)
    {
        _allowedGrantTypes.Clear();
        _allowedGrantTypes.AddRange(grantTypes);
        return this;
    }

    public ClientBuilder WithScopes(params string[] scopes)
    {
        _allowedScopes.Clear();
        _allowedScopes.AddRange(scopes);
        return this;
    }

    public ClientBuilder AsPublicClient()
    {
        _clientType = ClientType.Public;
        Secret = null;
        _requirePkce = true;
        return this;
    }

    public ClientBuilder AsConfidentialClient(string secret)
    {
        _clientType = ClientType.Confidential;
        Secret = secret;
        return this;
    }

    public ClientBuilder RequirePkce(bool require = true)
    {
        _requirePkce = require;
        return this;
    }

    public ClientBuilder AllowOfflineAccess(bool allow = true)
    {
        _allowOfflineAccess = allow;
        return this;
    }

    public CoreIdentClient Build() => new()
    {
        ClientId = _clientId,
        ClientName = _clientName,
        ClientType = _clientType,
        AllowedGrantTypes = _allowedGrantTypes.ToList(),
        AllowedScopes = _allowedScopes.ToList(),
        RequirePkce = _requirePkce,
        AllowOfflineAccess = _allowOfflineAccess,
        Enabled = true,
        CreatedAt = DateTime.UtcNow
    };
}
