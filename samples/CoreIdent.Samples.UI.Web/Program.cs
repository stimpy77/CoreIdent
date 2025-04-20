using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);

// Assume CoreIdent runs here - replace with actual URL if different
var coreIdentServerUrl = builder.Configuration["CoreIdentServerUrl"] ?? "https://localhost:7100"; // Default for dev

// Add services for the sample UI client app
builder.Services.AddRazorPages();

// --- Configure Cookie Authentication for the LOCAL Sample App Session ---
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login"; // Local login page
        options.AccessDeniedPath = "/Account/Error";
        options.ExpireTimeSpan = TimeSpan.FromHours(1); // Example session duration
        options.SlidingExpiration = true;
    });
// ----------------------------------------------------------------------

builder.Services.AddAuthorization();

// --- Add HttpClient for backend calls (e.g., token exchange) ---
builder.Services.AddHttpClient("CoreIdentApiClient", client =>
{
    client.BaseAddress = new Uri(coreIdentServerUrl);
});
// ------------------------------------------------------------

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Account/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// --- Use Authentication & Authorization for the LOCAL app ---
app.UseAuthentication();
app.UseAuthorization();
// ---------------------------------------------------------

app.MapRazorPages().RequireAuthorization(); // Require auth for Razor Pages by default

app.Run();
