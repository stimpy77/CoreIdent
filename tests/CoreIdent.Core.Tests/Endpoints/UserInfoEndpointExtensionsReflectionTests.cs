using System.Reflection;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Endpoints;

public sealed class UserInfoEndpointExtensionsReflectionTests
{
    [Fact]
    public void AddClaimValue_sets_initial_value_when_missing()
    {
        var dict = new Dictionary<string, object?>();

        InvokeAddClaimValue(dict, "name", "Alice");

        dict.ContainsKey("name").ShouldBeTrue("Dictionary should contain the inserted claim.");
        dict["name"].ShouldBe("Alice", "First value should be stored as a string.");
    }

    [Fact]
    public void AddClaimValue_promotes_string_to_array_on_second_value()
    {
        var dict = new Dictionary<string, object?>
        {
            ["name"] = "Alice"
        };

        InvokeAddClaimValue(dict, "name", "Bob");

        dict["name"].ShouldBeOfType<string[]>("Second value should promote existing string to string array.");
        ((string[])dict["name"]!).ShouldBe(new[] { "Alice", "Bob" }, "Array should contain both values in insertion order.");
    }

    [Fact]
    public void AddClaimValue_appends_to_existing_array_on_third_value()
    {
        var dict = new Dictionary<string, object?>
        {
            ["name"] = new[] { "Alice", "Bob" }
        };

        InvokeAddClaimValue(dict, "name", "Carol");

        ((string[])dict["name"]!).ShouldBe(new[] { "Alice", "Bob", "Carol" }, "Third value should append to existing array.");
    }

    [Fact]
    public void AddClaimValue_overwrites_non_string_existing_value()
    {
        var dict = new Dictionary<string, object?>
        {
            ["name"] = 123
        };

        InvokeAddClaimValue(dict, "name", "Alice");

        dict["name"].ShouldBe("Alice", "Non-string existing value should be replaced with the new string value.");
    }

    private static void InvokeAddClaimValue(IDictionary<string, object?> dest, string name, string value)
    {
        var method = typeof(CoreIdent.Core.Endpoints.UserInfoEndpointExtensions)
            .GetMethod("AddClaimValue", BindingFlags.NonPublic | BindingFlags.Static);

        method.ShouldNotBeNull("AddClaimValue should be present as a private static helper.");

        method!.Invoke(null, new object[] { dest, name, value });
    }
}
