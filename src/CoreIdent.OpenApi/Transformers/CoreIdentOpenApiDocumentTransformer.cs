using CoreIdent.Core.Configuration;
using CoreIdent.OpenApi.Configuration;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

namespace CoreIdent.OpenApi.Transformers;

internal sealed class CoreIdentOpenApiDocumentTransformer(
    CoreIdentOpenApiOptions options,
    IOptions<CoreIdentOptions> coreIdentOptions,
    IOptions<CoreIdentRouteOptions> routeOptions)
    : IOpenApiDocumentTransformer
{
    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);

        // Set basic document info
        document.Info = new()
        {
            Title = options.DocumentTitle,
            Version = options.DocumentVersion,
        };

        // Set server URL from issuer
        var issuer = coreIdentOptions.Value.Issuer;
        if (!string.IsNullOrWhiteSpace(issuer) && Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
        {
            var baseUrl = issuerUri.GetLeftPart(UriPartial.Authority) + issuerUri.AbsolutePath.TrimEnd('/');
            document.Servers = new List<OpenApiServer>
            {
                new()
                {
                    Url = baseUrl,
                }
            };
        }

        if (options.IncludeSecurityDefinitions)
        {
            document.Components ??= new OpenApiComponents();
            document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>(StringComparer.Ordinal);

            document.Components.SecuritySchemes["client_secret_basic"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "basic",
                In = ParameterLocation.Header,
                Description = "OAuth 2.0 client authentication using HTTP Basic (client_id:client_secret).",
            };

            document.Components.SecuritySchemes["client_secret_post"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Query,
                Name = "client_secret",
                Description = "OAuth 2.0 client authentication using request body parameters (client_id/client_secret). (Represented as an API key for tooling compatibility; the true location is form body, not query.)",
            };

            document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "Bearer token authentication using a JWT access token.",
            };

            var (authorizeUrl, tokenUrl) = ResolveOAuthUrls();

            document.Components.SecuritySchemes["authorization_code"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Description = "Authorization Code flow (PKCE required by CoreIdent).",
                Flows = new OpenApiOAuthFlows
                {
                    AuthorizationCode = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = authorizeUrl,
                        TokenUrl = tokenUrl,
                        Scopes = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["openid"] = "OpenID Connect scope",
                        }
                    }
                }
            };

            document.Components.SecuritySchemes["refresh_token"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Description = "Refresh Token grant (token refresh via the token endpoint). Note: refresh_token is not a standalone OAuth2 flow; this scheme is provided for tooling convenience.",
                Flows = new OpenApiOAuthFlows
                {
                    ClientCredentials = new OpenApiOAuthFlow
                    {
                        TokenUrl = tokenUrl,
                        Scopes = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["openid"] = "OpenID Connect scope",
                        }
                    }
                }
            };
        }

        return Task.CompletedTask;

        (Uri authorizeUrl, Uri tokenUrl) ResolveOAuthUrls()
        {
            var issuer = coreIdentOptions.Value.Issuer;
            if (!string.IsNullOrWhiteSpace(issuer) && Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
            {
                var routes = routeOptions.Value;
                var authorizePath = routes.CombineWithBase(routes.AuthorizePath);
                var tokenPath = routes.CombineWithBase(routes.TokenPath);

                return (new Uri(issuerUri, authorizePath), new Uri(issuerUri, tokenPath));
            }

            return (new Uri("https://example.invalid/auth/authorize"), new Uri("https://example.invalid/auth/token"));
        }
    }
}
