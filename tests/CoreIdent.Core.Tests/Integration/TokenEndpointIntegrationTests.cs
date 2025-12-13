using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using CoreIdent.Core.Endpoints;
using CoreIdent.Core.Extensions;
using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Shouldly;
using Xunit;

namespace CoreIdent.Core.Tests.Integration;

public class TokenEndpointIntegrationTests
{
    private const string Issuer = "https://issuer.example";
    private const string Audience = "https://api.example";
    private const string TestClientId = "test-client";
    private const string TestClientSecret = "test-secret";

    [Fact]
    public async Task Post_token_with_client_credentials_returns_access_token()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "scope", "api" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Client credentials grant should return 200 OK.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull("Response should deserialize to TokenResponse.");
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("Access token should be present.");
        tokenResponse.TokenType.ShouldBe("Bearer", "Token type should be Bearer.");
        tokenResponse.ExpiresIn.ShouldBeGreaterThan(0, "ExpiresIn should be positive.");
        tokenResponse.Scope.ShouldBe("api", "Granted scope should match requested scope.");
    }

    [Fact]
    public async Task Post_token_with_client_credentials_includes_jti_claim()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull();

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(tokenResponse.AccessToken);
        jwt.ShouldNotBeNull("Token should be a valid JWT.");

        var jti = jwt.Claims.FirstOrDefault(c => c.Type == "jti");
        jti.ShouldNotBeNull("JWT should contain jti claim for revocation support.");
        jti.Value.ShouldNotBeNullOrWhiteSpace("jti claim should have a value.");
    }

    [Fact]
    public async Task Post_token_with_invalid_client_returns_401()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes("unknown-client:wrong-secret")));

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Invalid client credentials should return 401.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidClient, "Error should be invalid_client.");
    }

    [Fact]
    public async Task Post_token_with_wrong_client_secret_returns_401()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            })
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:wrong-secret")));

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Wrong client secret should return 401.");
    }

    [Fact]
    public async Task Post_token_with_unsupported_grant_type_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "password" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Unsupported grant type should return 400.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.UnauthorizedClient, "Error should indicate unauthorized grant type.");
    }

    [Fact]
    public async Task Post_token_with_invalid_scope_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "scope", "not-allowed-scope" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Invalid scope should return 400.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidScope, "Error should be invalid_scope.");
    }

    [Fact]
    public async Task Post_token_with_refresh_token_returns_new_tokens()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var originalRefreshToken = new CoreIdentRefreshToken
        {
            Handle = "original-refresh-token",
            SubjectId = "user-123",
            ClientId = TestClientId,
            FamilyId = "family-1",
            Scopes = ["openid", "api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        await refreshTokenStore.StoreAsync(originalRefreshToken);

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "original-refresh-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK, "Refresh token grant should return 200 OK.");

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        tokenResponse.ShouldNotBeNull();
        tokenResponse.AccessToken.ShouldNotBeNullOrWhiteSpace("New access token should be present.");
        tokenResponse.RefreshToken.ShouldNotBeNullOrWhiteSpace("New refresh token should be present.");
        tokenResponse.RefreshToken.ShouldNotBe("original-refresh-token", "Refresh token should be rotated.");
    }

    [Fact]
    public async Task Refresh_token_rotation_consumes_old_token()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var originalRefreshToken = new CoreIdentRefreshToken
        {
            Handle = "rotation-test-token",
            SubjectId = "user-456",
            ClientId = TestClientId,
            FamilyId = "family-2",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        await refreshTokenStore.StoreAsync(originalRefreshToken);

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "rotation-test-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var storedToken = await refreshTokenStore.GetAsync("rotation-test-token");
        storedToken.ShouldNotBeNull();
        storedToken.ConsumedAt.ShouldNotBeNull("Original refresh token should be marked as consumed.");
    }

    [Fact]
    public async Task Reusing_consumed_refresh_token_revokes_family()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var familyId = "theft-detection-family";

        var originalToken = new CoreIdentRefreshToken
        {
            Handle = "theft-test-token",
            SubjectId = "user-789",
            ClientId = TestClientId,
            FamilyId = familyId,
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        await refreshTokenStore.StoreAsync(originalToken);

        var firstResponse = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "theft-test-token" }
        });
        firstResponse.StatusCode.ShouldBe(HttpStatusCode.OK, "First use should succeed.");

        var secondResponse = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "theft-test-token" }
        });
        secondResponse.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Reusing consumed token should fail.");

        var errorResponse = await secondResponse.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidGrant, "Error should be invalid_grant.");

        var firstResponseContent = await firstResponse.Content.ReadFromJsonAsync<TokenResponse>();
        var newToken = await refreshTokenStore.GetAsync(firstResponseContent!.RefreshToken!);
        newToken.ShouldNotBeNull();
        newToken.IsRevoked.ShouldBeTrue("New token in family should be revoked due to theft detection.");
    }

    [Fact]
    public async Task Post_token_with_expired_refresh_token_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var expiredToken = new CoreIdentRefreshToken
        {
            Handle = "expired-token",
            SubjectId = "user-expired",
            ClientId = TestClientId,
            FamilyId = "expired-family",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow.AddDays(-10),
            ExpiresAt = DateTime.UtcNow.AddDays(-3)
        };
        await refreshTokenStore.StoreAsync(expiredToken);

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "expired-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Expired refresh token should return 400.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidGrant);
    }

    [Fact]
    public async Task Post_token_with_revoked_refresh_token_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var revokedToken = new CoreIdentRefreshToken
        {
            Handle = "revoked-token",
            SubjectId = "user-revoked",
            ClientId = TestClientId,
            FamilyId = "revoked-family",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = true
        };
        await refreshTokenStore.StoreAsync(revokedToken);

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "revoked-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Revoked refresh token should return 400.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidGrant);
    }

    [Fact]
    public async Task Post_token_with_wrong_client_for_refresh_token_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var refreshTokenStore = host.Services.GetRequiredService<IRefreshTokenStore>();
        var token = new CoreIdentRefreshToken
        {
            Handle = "other-client-token",
            SubjectId = "user-other",
            ClientId = "other-client",
            FamilyId = "other-family",
            Scopes = ["api"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };
        await refreshTokenStore.StoreAsync(token);

        var response = await PostTokenRequestAsync(client, new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", "other-client-token" }
        });

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Using another client's refresh token should fail.");

        var errorResponse = await response.Content.ReadFromJsonAsync<TokenErrorResponse>();
        errorResponse.ShouldNotBeNull();
        errorResponse.Error.ShouldBe(TokenErrors.InvalidGrant);
    }

    [Fact]
    public async Task Post_token_without_client_authentication_returns_401()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        var response = await client.PostAsync("/auth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" }
        }));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "Missing client authentication should return 401.");
    }

    [Fact]
    public async Task Post_token_with_non_form_content_returns_400()
    {
        using var rsa = RSA.Create(2048);
        using var host = await CreateHostAsync(rsa);
        using var client = host.GetTestClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new StringContent("{\"grant_type\":\"client_credentials\"}", Encoding.UTF8, "application/json")
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "Non-form content should return 400.");
    }

    private static async Task<HttpResponseMessage> PostTokenRequestAsync(HttpClient client, Dictionary<string, string> parameters)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/token")
        {
            Content = new FormUrlEncodedContent(parameters)
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestClientId}:{TestClientSecret}")));

        return await client.SendAsync(request);
    }

    private static async Task<IHost> CreateHostAsync(RSA rsa)
    {
        var rsaPem = rsa.ExportRSAPrivateKeyPem();

        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddLogging();

                        services.AddCoreIdent(options =>
                        {
                            options.Issuer = Issuer;
                            options.Audience = Audience;
                            options.AccessTokenLifetime = TimeSpan.FromMinutes(15);
                            options.RefreshTokenLifetime = TimeSpan.FromDays(7);
                        });

                        services.AddSigningKey(o => o.UseRsaPem(rsaPem));
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();

                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapCoreIdentTokenEndpoint();
                        });
                    });
            });

        var host = await builder.StartAsync();

        var clientStore = host.Services.GetRequiredService<IClientStore>();
        await clientStore.CreateAsync(new CoreIdentClient
        {
            ClientId = TestClientId,
            ClientSecretHash = host.Services.GetRequiredService<CoreIdent.Core.Services.IClientSecretHasher>().HashSecret(TestClientSecret),
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            AllowedGrantTypes = [GrantTypes.ClientCredentials, GrantTypes.RefreshToken],
            AllowedScopes = ["openid", "profile", "api"],
            AllowOfflineAccess = true,
            AccessTokenLifetimeSeconds = 900,
            RefreshTokenLifetimeSeconds = 604800,
            Enabled = true,
            CreatedAt = DateTime.UtcNow
        });

        return host;
    }
}
