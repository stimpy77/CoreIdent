using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Linq;
using CoreIdent.Testing.Fixtures;
using Microsoft.OpenApi;
using Microsoft.OpenApi.Reader;
using Shouldly;

namespace CoreIdent.Integration.Tests.Infrastructure;

public sealed class OpenApiFixtureTests : CoreIdentTestFixture
{
    [Fact]
    public async Task OpenApiDocument_Endpoint_Returns200_AndContainsExpectedPaths()
    {
        var response = await Client.GetAsync("/openapi/v1.json");

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace("Expected OpenAPI document body to be non-empty");

        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("openapi", out var openapiVersion).ShouldBeTrue("Expected OpenAPI document to contain 'openapi' property");
        openapiVersion.GetString().ShouldNotBeNullOrWhiteSpace("Expected OpenAPI version string to be present");

        doc.RootElement.TryGetProperty("paths", out var paths).ShouldBeTrue("Expected OpenAPI document to contain 'paths' property");

        paths.TryGetProperty("/auth/token", out _).ShouldBeTrue("Expected OpenAPI to contain /auth/token path");
        paths.TryGetProperty("/auth/revoke", out _).ShouldBeTrue("Expected OpenAPI to contain /auth/revoke path");
        paths.TryGetProperty("/auth/introspect", out _).ShouldBeTrue("Expected OpenAPI to contain /auth/introspect path");
        paths.TryGetProperty("/auth/userinfo", out _).ShouldBeTrue("Expected OpenAPI to contain /auth/userinfo path");
        paths.TryGetProperty("/.well-known/openid-configuration", out _).ShouldBeTrue("Expected OpenAPI to contain /.well-known/openid-configuration path");
        paths.TryGetProperty("/.well-known/jwks.json", out _).ShouldBeTrue("Expected OpenAPI to contain /.well-known/jwks.json path");
    }

    [Fact]
    public async Task OpenApiDocument_DefinesSecuritySchemes()
    {
        var response = await Client.GetAsync("/openapi/v1.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("components", out var components).ShouldBeTrue("Expected OpenAPI document to contain 'components' property");
        components.TryGetProperty("securitySchemes", out var securitySchemes).ShouldBeTrue("Expected OpenAPI document to contain 'components.securitySchemes'");

        securitySchemes.TryGetProperty("client_secret_basic", out _).ShouldBeTrue("Expected security scheme 'client_secret_basic' to be defined");
        securitySchemes.TryGetProperty("client_secret_post", out _).ShouldBeTrue("Expected security scheme 'client_secret_post' to be defined");
        securitySchemes.TryGetProperty("authorization_code", out _).ShouldBeTrue("Expected security scheme 'authorization_code' to be defined");
        securitySchemes.TryGetProperty("Bearer", out _).ShouldBeTrue("Expected security scheme 'Bearer' to be defined");
    }

    [Fact]
    public async Task OpenApiDocument_DefinesExamples_ForKeyOAuthEndpoints()
    {
        var response = await Client.GetAsync("/openapi/v1.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("paths", out var paths).ShouldBeTrue("Expected OpenAPI document to contain 'paths' property");

        AssertFormExamples(paths, "/auth/token", new[] { "client_credentials", "authorization_code", "refresh_token" });
        AssertFormExamples(paths, "/auth/revoke", new[] { "access_token", "refresh_token" });
        AssertFormExamples(paths, "/auth/introspect", new[] { "access_token", "refresh_token" });

        static void AssertFormExamples(JsonElement paths, string path, string[] expectedExampleKeys)
        {
            paths.TryGetProperty(path, out var pathItem).ShouldBeTrue($"Expected OpenAPI to contain {path} path");
            pathItem.TryGetProperty("post", out var post).ShouldBeTrue($"Expected OpenAPI to contain POST {path} operation");

            post.TryGetProperty("requestBody", out var requestBody).ShouldBeTrue($"Expected POST {path} to contain requestBody");
            requestBody.TryGetProperty("content", out var content).ShouldBeTrue($"Expected POST {path} requestBody to contain content");
            content.TryGetProperty("application/x-www-form-urlencoded", out var form).ShouldBeTrue($"Expected POST {path} to define application/x-www-form-urlencoded content");
            form.TryGetProperty("examples", out var examples).ShouldBeTrue($"Expected POST {path} form content to contain examples");

            foreach (var key in expectedExampleKeys)
            {
                examples.TryGetProperty(key, out _).ShouldBeTrue($"Expected POST {path} to define example '{key}'");
            }
        }
    }

    [Fact]
    public async Task OpenApiDocument_EmitsSchemas_WithDescriptions_ForKeyModels()
    {
        var response = await Client.GetAsync("/openapi/v1.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("components", out var components).ShouldBeTrue("Expected OpenAPI document to contain 'components' property");
        components.TryGetProperty("schemas", out var schemas).ShouldBeTrue("Expected OpenAPI document to contain 'components.schemas'");

        AssertSchemaHasDescription(schemas, "TokenResponse");
        AssertSchemaHasDescription(schemas, "TokenIntrospectionResponse");

        static void AssertSchemaHasDescription(JsonElement schemas, string schemaName)
        {
            schemas.TryGetProperty(schemaName, out var schema).ShouldBeTrue($"Expected schema '{schemaName}' to exist in components.schemas");
            schema.TryGetProperty("description", out var description).ShouldBeTrue($"Expected schema '{schemaName}' to have a description");
            description.GetString().ShouldNotBeNullOrWhiteSpace($"Expected schema '{schemaName}' description to be non-empty");
        }
    }

    [Fact]
    public async Task OpenApiDocument_DefinesOperationSecurityRequirements()
    {
        var response = await Client.GetAsync("/openapi/v1.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        doc.RootElement.TryGetProperty("paths", out var paths).ShouldBeTrue("Expected OpenAPI document to contain 'paths' property");

        AssertHasSecurity(paths, "/auth/userinfo", "get", new[] { "Bearer" });
        AssertHasSecurity(paths, "/auth/token", "post", new[] { "client_secret_basic", "client_secret_post" });
        AssertHasSecurity(paths, "/auth/revoke", "post", new[] { "client_secret_basic", "client_secret_post" });
        AssertHasSecurity(paths, "/auth/introspect", "post", new[] { "client_secret_basic", "client_secret_post" });

        static void AssertHasSecurity(JsonElement paths, string path, string method, string[] expectedSchemes)
        {
            paths.TryGetProperty(path, out var pathItem).ShouldBeTrue($"Expected OpenAPI to contain {path} path");
            pathItem.TryGetProperty(method, out var op).ShouldBeTrue($"Expected OpenAPI to contain {method.ToUpperInvariant()} {path} operation");

            op.TryGetProperty("security", out var security).ShouldBeTrue($"Expected {method.ToUpperInvariant()} {path} to have a security requirement");
            security.ValueKind.ShouldBe(JsonValueKind.Array, $"Expected {method.ToUpperInvariant()} {path} security to be an array");

            // Expect one requirement object per alternative scheme.
            var found = new HashSet<string>(StringComparer.Ordinal);
            foreach (var req in security.EnumerateArray())
            {
                if (req.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var prop in req.EnumerateObject())
                {
                    found.Add(ResolveSchemeId(prop.Name));
                }
            }

            foreach (var scheme in expectedSchemes)
            {
                found.Contains(scheme).ShouldBeTrue($"Expected {method.ToUpperInvariant()} {path} security to include scheme '{scheme}'");
            }

            static string ResolveSchemeId(string key)
            {
                // ASP.NET Core OpenAPI serializes security requirement keys as $ref-like strings:
                // '#/components/securitySchemes/Bearer'
                var idx = key.LastIndexOf('/');
                return idx >= 0 ? key[(idx + 1)..] : key;
            }
        }
    }

    [Fact]
    public async Task OpenApiDocument_Validates_WithOpenApiNet()
    {
        var response = await Client.GetAsync("/openapi/v1.json");
        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Expected GET /openapi/v1.json to return 200 OK");

        var json = await response.Content.ReadAsStringAsync();

        var node = JsonNode.Parse(json).ShouldNotBeNull("Expected OpenAPI JSON to parse as JsonNode");

        var reader = new OpenApiJsonReader();
        var result = reader.Read(node!, new Uri("https://example.invalid/openapi/v1.json"), new OpenApiReaderSettings());

        result.Diagnostic.ShouldNotBeNull("Expected OpenAPI reader to return diagnostics");
        result.Diagnostic.Errors.Count.ShouldBe(0, "Expected OpenAPI reader diagnostic to contain no errors");

        result.Document.ShouldNotBeNull("Expected OpenAPI reader to produce an OpenApiDocument");

        // Validate the OpenApiDocument object model.
        var ruleSet = ValidationRuleSet.GetDefaultRuleSet();
        var validator = new OpenApiValidator(ruleSet);
        validator.Visit(result.Document);

        validator.Errors.Count().ShouldBe(0, "Expected OpenAPI validator to report no errors");
    }
}
