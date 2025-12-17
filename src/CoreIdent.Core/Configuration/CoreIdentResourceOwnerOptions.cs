using System.Security.Claims;
using CoreIdent.Core.Models;
using Microsoft.AspNetCore.Http;

namespace CoreIdent.Core.Configuration;

public sealed class CoreIdentResourceOwnerOptions
{
    public string ClientId { get; set; } = "resource_owner";

    public Func<HttpContext, CoreIdentUser, CancellationToken, Task<IResult?>>? RegisterHandler { get; set; }

    public Func<HttpContext, CoreIdentUser, TokenResponse, CancellationToken, Task<IResult?>>? LoginHandler { get; set; }

    public Func<HttpContext, CoreIdentUser, IReadOnlyList<Claim>, CancellationToken, Task<IResult?>>? ProfileHandler { get; set; }
}
