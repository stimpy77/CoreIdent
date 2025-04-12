using CoreIdent.Core.Configuration;
using CoreIdent.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

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
    options.SigningKeySecret = "MySuperSecretTestHostKeyLongEnough";
    options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
    options.RefreshTokenLifetime = TimeSpan.FromDays(1);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Map CoreIdent endpoints under the /auth base path
app.MapCoreIdentEndpoints("/auth"); // Specify base path

app.Run();

// Make Program accessible for WebApplicationFactory
public partial class Program { }
