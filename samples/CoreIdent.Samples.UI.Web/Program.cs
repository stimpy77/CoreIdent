using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using CoreIdent.Core.Extensions;  // Add CoreIdent API endpoints

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Error";
    });
builder.Services.AddAuthorization();
builder.Services.AddHttpClient();
// Register CoreIdent API endpoints (convention over configuration)
builder.Services.AddCoreIdent(options => { /* defaults: BasePath="/auth" */ });

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Account/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Redirect minimal API GET /auth/consent to the Razor consent UI
app.MapGet("/auth/consent", (HttpContext context) =>
{
    var qs = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
    return Results.Redirect($"/Account/Consent{qs}");
}).RequireAuthorization();

app.MapRazorPages();
// Map CoreIdent endpoints under BasePath (e.g., /auth)
app.MapCoreIdentEndpoints();
app.Run();
