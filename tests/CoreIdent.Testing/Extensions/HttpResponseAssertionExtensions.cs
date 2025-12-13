using System.Net;
using System.Net.Http.Json;
using Shouldly;

namespace CoreIdent.Testing.Extensions;

public static class HttpResponseAssertionExtensions
{
    public static async Task<T> ShouldBeSuccessfulWithContent<T>(this HttpResponseMessage response) where T : class
    {
        response.IsSuccessStatusCode.ShouldBeTrue(
            $"Expected success but got {(int)response.StatusCode} {response.StatusCode}: {await response.Content.ReadAsStringAsync()}");

        var content = await response.Content.ReadFromJsonAsync<T>();
        content.ShouldNotBeNull($"Expected JSON content deserializable to {typeof(T).Name}.");
        return content;
    }

    public static Task ShouldBeSuccessful(this HttpResponseMessage response)
    {
        response.IsSuccessStatusCode.ShouldBeTrue(
            $"Expected success but got {(int)response.StatusCode} {response.StatusCode}.");
        return Task.CompletedTask;
    }

    public static Task ShouldBeUnauthorized(this HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Expected 401 Unauthorized.");
        return Task.CompletedTask;
    }

    public static async Task ShouldBeBadRequest(this HttpResponseMessage response, string? contains = null)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Expected 400 BadRequest.");

        if (contains is not null)
        {
            var body = await response.Content.ReadAsStringAsync();
            body.ShouldContain(contains);
        }
    }
}
