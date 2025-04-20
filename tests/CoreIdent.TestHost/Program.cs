using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using CoreIdent.TestHost;
using System.IO;
using Microsoft.Extensions.Logging;

// Removed public partial Program class from this file to avoid top-level statement conflict.

var builder = WebApplication.CreateBuilder(args);

// --- LOGGING CONFIGURATION FOR TEST HOST ---
// Configure console logging with information level or higher
var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
Directory.CreateDirectory(logDir);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Set minimum log level globally to capture all relevant diagnostic information
builder.Logging.SetMinimumLevel(LogLevel.Debug);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer(); 
builder.Services.AddSwaggerGen();

// Add CoreIdent services with minimal valid configuration for testing
builder.Services.AddCoreIdent(options =>
{
    options.Issuer = "urn:test-issuer";
    options.Audience = "urn:test-audience";
    // Use a secure, sufficiently long key (at least 32 bytes / 256 bits recommended for HS256)
    options.SigningKeySecret = "MySuperSecretTestHostKeyLongEnough32Bytes";
    options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
    options.RefreshTokenLifetime = TimeSpan.FromMinutes(10); // Short lifetime for testing expiration, > AccessTokenLifetime
});

// Add antiforgery services for consent POST endpoint
builder.Services.AddAntiforgery();

// Register authentication schemes.
// Set Cookies as the default scheme for authentication and sign-in.
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = "Cookies";
        options.DefaultSignInScheme = "Cookies"; // Important for context.SignInAsync in /test-login
        options.DefaultChallengeScheme = "Cookies"; // Redirect to login if Cookies auth fails
    })
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>(
        "TestAuth", options => { }) // Keep the header-based scheme available
    .AddCookie("Cookies", options => {
        options.Cookie.Name = "CoreIdent.Tests.Auth";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.LoginPath = "/auth/login"; // Set the login path for challenge
    });

// Register authorization
builder.Services.AddAuthorization();

// --- Keep Storage Configuration Commented Out in TestHost Program.cs ---
// builder.Services.AddDbContext<CoreIdentDbContext>(options =>
//     options.UseSqlite($"DataSource=file:memdb-{Guid.NewGuid()}?mode=memory&cache=shared"), 
//     ServiceLifetime.Scoped);
// builder.Services.AddCoreIdentEntityFrameworkStores<CoreIdentDbContext>();
// --- End Comment Out ---

// Let the WebApplicationFactory configure the DbContext and stores for tests.

var app = builder.Build();

// --- Keep migration logic Commented Out in TestHost Program.cs ---
// using (var scope = app.Services.CreateScope())
// {
//     var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
//     dbContext.Database.Migrate(); 
// }
// --- End Comment Out ---

// Configure a simple exception handler for the test environment
// app.UseExceptionHandler(exceptionHandlerApp =>
// {
//     exceptionHandlerApp.Run(async context =>
//     {
//         context.Response.StatusCode = StatusCodes.Status500InternalServerError;
//         await context.Response.WriteAsync("An unexpected error occurred.");
//     });
// });

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Explicitly add routing before auth/authz/antiforgery
app.UseRouting();

// Enable authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Add antiforgery *after* auth and routing
app.UseAntiforgery(); 

// app.UseHttpsRedirection(); // REMOVED for test host - factory usually uses HTTP

app.MapCoreIdentEndpoints();

// Add a test-only login endpoint for integration test authentication
app.MapPost("/test-login", async (HttpContext context) =>
{
    var testUserId = context.Request.Query["userId"].ToString();
    var testUserEmail = context.Request.Query["email"].ToString();
    var scheme = context.Request.Query["scheme"].FirstOrDefault() ?? "TestAuth";
    
    if (string.IsNullOrWhiteSpace(testUserId) || string.IsNullOrWhiteSpace(testUserEmail))
        return Results.BadRequest("Missing userId or email");

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, testUserId),
        new(ClaimTypes.Name, testUserEmail),
        new(ClaimTypes.Email, testUserEmail)
    };
    var identity = new ClaimsIdentity(claims, scheme);
    var principal = new ClaimsPrincipal(identity);

    // Log user claims for diagnostics
    var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TestHost.TestLogin");
    logger.LogInformation("[TEST-LOGIN DEBUG] Issuing auth cookie for userId={UserId}, email={Email}, scheme={Scheme}", testUserId, testUserEmail, scheme);
    foreach (var claim in claims)
    {
        logger.LogInformation("[TEST-LOGIN DEBUG] Claim: {Type} = {Value}", claim.Type, claim.Value);
    }

    // Sign in using the specified scheme (should be "Cookies" from the test)
    await context.SignInAsync(scheme, principal); 

    // Log response headers to check for Set-Cookie
    var cookieHeader = context.Response.Headers["Set-Cookie"].ToString();
    logger.LogInformation("[TEST-LOGIN DEBUG] Response Set-Cookie Header: {SetCookieHeader}", 
        string.IsNullOrWhiteSpace(cookieHeader) ? "<Not Set>" : cookieHeader);

    return Results.Ok($"Authenticated as {testUserEmail} using scheme {scheme}");
});

// Add the /test-auth-check endpoint to verify authentication status
app.MapGet("/test-auth-check", (HttpContext context) =>
{
    var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TestHost.TestAuthCheck");
    var isAuthenticated = context.User?.Identity?.IsAuthenticated ?? false;
    var claims = context.User?.Claims.Select(c => new { c.Type, c.Value }).ToList();

    logger.LogInformation("[TEST-AUTH-CHECK] IsAuthenticated={IsAuthenticated}, AuthType={AuthType}, Claims={ClaimsCount}", 
        isAuthenticated, 
        context.User?.Identity?.AuthenticationType,
        claims?.Count ?? 0);

    if (claims != null)
    {
        foreach (var claim in claims)
        {
            logger.LogInformation("[TEST-AUTH-CHECK] Claim: {Type}={Value}", claim.Type, claim.Value);
        }
    }

    return Results.Ok(new { 
        IsAuthenticated = isAuthenticated, 
        AuthenticationType = context.User?.Identity?.AuthenticationType,
        UserId = context.User?.FindFirstValue(ClaimTypes.NameIdentifier),
        Email = context.User?.FindFirstValue(ClaimTypes.Email),
        Claims = claims
    });
});

app.Run();
