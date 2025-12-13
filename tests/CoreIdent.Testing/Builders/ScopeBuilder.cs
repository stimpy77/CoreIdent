using CoreIdent.Core.Models;

namespace CoreIdent.Testing.Builders;

public sealed class ScopeBuilder
{
    private string _name = $"scope-{Guid.NewGuid():N}";
    private string? _displayName;
    private string? _description;
    private bool _required;
    private bool _emphasize;
    private bool _showInDiscoveryDocument = true;
    private readonly List<string> _userClaims = [];

    public ScopeBuilder WithName(string name)
    {
        _name = name;
        return this;
    }

    public ScopeBuilder WithDisplayName(string? displayName)
    {
        _displayName = displayName;
        return this;
    }

    public ScopeBuilder WithDescription(string? description)
    {
        _description = description;
        return this;
    }

    public ScopeBuilder Required(bool required = true)
    {
        _required = required;
        return this;
    }

    public ScopeBuilder Emphasize(bool emphasize = true)
    {
        _emphasize = emphasize;
        return this;
    }

    public ScopeBuilder ShowInDiscoveryDocument(bool show = true)
    {
        _showInDiscoveryDocument = show;
        return this;
    }

    public ScopeBuilder WithUserClaims(params string[] claims)
    {
        _userClaims.Clear();
        _userClaims.AddRange(claims);
        return this;
    }

    public CoreIdentScope Build() => new()
    {
        Name = _name,
        DisplayName = _displayName,
        Description = _description,
        Required = _required,
        Emphasize = _emphasize,
        ShowInDiscoveryDocument = _showInDiscoveryDocument,
        UserClaims = _userClaims.ToList()
    };
}
