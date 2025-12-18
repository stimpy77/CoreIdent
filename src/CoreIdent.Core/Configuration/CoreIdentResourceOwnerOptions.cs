using System.Security.Claims;
using CoreIdent.Core.Models;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Configuration;

/// <summary>
/// Options for resource owner endpoints.
/// </summary>
public sealed class CoreIdentResourceOwnerOptions
{
    /// <summary>
    /// Client identifier used for resource owner flows.
    /// </summary>
    public string ClientId { get; set; } = "resource_owner";

    /// <summary>
    /// Optional registration handler.
    /// </summary>
    public Func<HttpContext, CoreIdentUser, CancellationToken, Task<IResult?>>? RegisterHandler { get; set; }

    /// <summary>
    /// Optional login handler.
    /// </summary>
    public Func<HttpContext, CoreIdentUser, TokenResponse, CancellationToken, Task<IResult?>>? LoginHandler { get; set; }

    /// <summary>
    /// Optional profile handler.
    /// </summary>
    public Func<HttpContext, CoreIdentUser, IReadOnlyList<Claim>, CancellationToken, Task<IResult?>>? ProfileHandler { get; set; }
}
