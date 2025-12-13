using CoreIdent.Core.Models;
using Shouldly;

namespace CoreIdent.Core.Tests.Models;

public class StandardScopesTests
{
    [Fact]
    public void All_contains_standard_scopes_including_offline_access()
    {
        StandardScopes.All.ShouldContain(StandardScopes.OpenId, "All should contain openid scope");
        StandardScopes.All.ShouldContain(StandardScopes.Profile, "All should contain profile scope");
        StandardScopes.All.ShouldContain(StandardScopes.Email, "All should contain email scope");
        StandardScopes.All.ShouldContain(StandardScopes.Address, "All should contain address scope");
        StandardScopes.All.ShouldContain(StandardScopes.Phone, "All should contain phone scope");
        StandardScopes.All.ShouldContain(StandardScopes.OfflineAccess, "All should contain offline_access scope");
    }
}
