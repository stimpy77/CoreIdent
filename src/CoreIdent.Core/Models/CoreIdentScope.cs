namespace CoreIdent.Core.Models;

public class CoreIdentScope
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool Required { get; set; } = false;
    public bool Emphasize { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public ICollection<string> UserClaims { get; set; } = [];
}
