using CoreIdent.Passkeys.Stores;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using CoreIdent.Testing.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace CoreIdent.Integration.Tests.Passkeys;

public sealed class PasskeyEfStoreWiringFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public void Passkey_store_is_ef_core_implementation_in_test_host()
    {
        using var scope = Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IPasskeyCredentialStore>();
        store.ShouldBeOfType<EfPasskeyCredentialStore>();
    }
}
