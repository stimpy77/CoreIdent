using CoreIdent.OpenApi.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using System.Text.Json.Nodes;

namespace CoreIdent.OpenApi.Transformers;

internal sealed class CoreIdentOpenApiOperationTransformer(CoreIdentOpenApiOptions options)
    : IOpenApiOperationTransformer
{
    public Task TransformAsync(OpenApiOperation operation, OpenApiOperationTransformerContext context, CancellationToken cancellationToken)
    {
        if (!options.IncludeSecurityDefinitions)
        {
            return Task.CompletedTask;
        }

        var relativePath = context.Description.RelativePath ?? string.Empty;
        var httpMethod = context.Description.HttpMethod ?? string.Empty;

        AddExamples(operation, relativePath, httpMethod);
        if (context.Document is not null)
        {
            AddSecurity(operation, relativePath, context.Document);
        }

        return Task.CompletedTask;
    }

    private static void AddSecurity(OpenApiOperation operation, string relativePath, OpenApiDocument document)
    {
        var path = "/" + relativePath.TrimStart('/');

        if (path.EndsWith("/userinfo", StringComparison.Ordinal))
        {
            operation.Security = new List<OpenApiSecurityRequirement>
            {
                SecurityRequirement(document, "Bearer"),
            };

            return;
        }

        if (path.EndsWith("/token", StringComparison.Ordinal)
            || path.EndsWith("/revoke", StringComparison.Ordinal)
            || path.EndsWith("/introspect", StringComparison.Ordinal))
        {
            operation.Security = new List<OpenApiSecurityRequirement>
            {
                SecurityRequirement(document, "client_secret_basic"),
                SecurityRequirement(document, "client_secret_post"),
            };
        }
    }

    private static OpenApiSecurityRequirement SecurityRequirement(OpenApiDocument document, string schemeId)
    {
        return new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference(schemeId, document, externalResource: string.Empty)] = new List<string>(),
        };
    }

    private static void AddExamples(OpenApiOperation operation, string relativePath, string httpMethod)
    {
        var path = "/" + relativePath.TrimStart('/');
        if (!string.Equals(httpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (path.EndsWith("/token", StringComparison.Ordinal))
        {
            EnsureFormUrlEncodedRequest(operation, new Dictionary<string, OpenApiExample>(StringComparer.Ordinal)
            {
                ["client_credentials"] = new()
                {
                    Summary = "Client credentials",
                    Value = JsonValue.Create("grant_type=client_credentials&scope=openid"),
                },
                ["authorization_code"] = new()
                {
                    Summary = "Authorization code (PKCE)",
                    Value = JsonValue.Create("grant_type=authorization_code&code=CODE&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier=VERIFIER"),
                },
                ["refresh_token"] = new()
                {
                    Summary = "Refresh token",
                    Value = JsonValue.Create("grant_type=refresh_token&refresh_token=REFRESH_TOKEN"),
                },
            });

            EnsureJsonResponse(operation, StatusCodes.Status200OK.ToString(), new OpenApiExample
            {
                Summary = "Token response",
                Value = new JsonObject
                {
                    ["access_token"] = "eyJ...",
                    ["token_type"] = "Bearer",
                    ["expires_in"] = 900,
                    ["refresh_token"] = "REFRESH_TOKEN",
                }
            });

            return;
        }

        if (path.EndsWith("/revoke", StringComparison.Ordinal))
        {
            EnsureFormUrlEncodedRequest(operation, new Dictionary<string, OpenApiExample>(StringComparer.Ordinal)
            {
                ["access_token"] = new()
                {
                    Summary = "Revoke access token",
                    Value = JsonValue.Create("token=ACCESS_TOKEN&token_type_hint=access_token"),
                },
                ["refresh_token"] = new()
                {
                    Summary = "Revoke refresh token",
                    Value = JsonValue.Create("token=REFRESH_TOKEN&token_type_hint=refresh_token"),
                },
            });

            return;
        }

        if (path.EndsWith("/introspect", StringComparison.Ordinal))
        {
            EnsureFormUrlEncodedRequest(operation, new Dictionary<string, OpenApiExample>(StringComparer.Ordinal)
            {
                ["access_token"] = new()
                {
                    Summary = "Introspect access token",
                    Value = JsonValue.Create("token=ACCESS_TOKEN&token_type_hint=access_token"),
                },
                ["refresh_token"] = new()
                {
                    Summary = "Introspect refresh token",
                    Value = JsonValue.Create("token=REFRESH_TOKEN&token_type_hint=refresh_token"),
                },
            });

            EnsureJsonResponse(operation, StatusCodes.Status200OK.ToString(), new OpenApiExample
            {
                Summary = "Active token response",
                Value = new JsonObject
                {
                    ["active"] = true,
                    ["client_id"] = "example_client",
                    ["token_type"] = "access_token",
                    ["scope"] = "openid",
                }
            });

            return;
        }
    }

    private static void EnsureFormUrlEncodedRequest(OpenApiOperation operation, IDictionary<string, OpenApiExample> examples)
    {
        var requestBody = operation.RequestBody as OpenApiRequestBody;
        if (requestBody is null)
        {
            requestBody = new OpenApiRequestBody
            {
                Required = true,
            };
            operation.RequestBody = requestBody;
        }

        requestBody.Content ??= new Dictionary<string, OpenApiMediaType>(StringComparer.Ordinal);

        if (!requestBody.Content.TryGetValue("application/x-www-form-urlencoded", out var mediaType))
        {
            mediaType = new OpenApiMediaType
            {
                Schema = new OpenApiSchema
                {
                    Type = JsonSchemaType.String,
                    Description = "Form-encoded request body",
                },
            };

            requestBody.Content["application/x-www-form-urlencoded"] = mediaType;
        }

        mediaType.Examples ??= new Dictionary<string, IOpenApiExample>(StringComparer.Ordinal);
        foreach (var (key, example) in examples)
        {
            mediaType.Examples[key] = example;
        }
    }

    private static void EnsureJsonResponse(OpenApiOperation operation, string statusCode, OpenApiExample example)
    {
        operation.Responses ??= new OpenApiResponses();

        if (!operation.Responses.TryGetValue(statusCode, out var responseObj)
            || responseObj is not OpenApiResponse response)
        {
            response = new OpenApiResponse { Description = string.Empty };
            operation.Responses[statusCode] = response;
        }

        response.Content ??= new Dictionary<string, OpenApiMediaType>(StringComparer.Ordinal);
        if (!response.Content.TryGetValue("application/json", out var mediaType))
        {
            mediaType = new OpenApiMediaType();
            response.Content["application/json"] = mediaType;
        }

        mediaType.Example = example.Value;
    }
}
