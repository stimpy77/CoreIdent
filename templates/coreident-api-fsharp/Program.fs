namespace CoreIdentApi

open System
open System.Collections.Generic
open System.Linq
open System.Text.Json
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.Configuration
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.DependencyInjection.Extensions
open Microsoft.Extensions.Hosting
open CoreIdent.Core.Extensions
open CoreIdent.Core.Models
open CoreIdent.Core.Services
open CoreIdent.Core.Stores

//#if (useEfCore)
open CoreIdent.Storage.EntityFrameworkCore
open CoreIdent.Storage.EntityFrameworkCore.Extensions
open CoreIdent.Storage.EntityFrameworkCore.Models
open Microsoft.EntityFrameworkCore
//#endif

//#if (usePasswordless)
type DevEmailSender() =
    interface IEmailSender with
        member _.SendAsync(message: EmailMessage, ct: System.Threading.CancellationToken) =
            Console.WriteLine($"[CoreIdent] Email to={message.To} subject={message.Subject}")
            Console.WriteLine(message.HtmlBody)
            System.Threading.Tasks.Task.CompletedTask
//#endif

module Program =

    let private getRequiredConfigValue (builder: WebApplicationBuilder) (key: string) : string =
        match builder.Configuration.[key] with
        | null
        | "" -> invalidOp $"Missing required configuration value: {key}"
        | value -> value

    [<EntryPoint>]
    let main args =
        let builder = WebApplication.CreateBuilder(args)

        builder.Services.AddCoreIdent(fun o ->
            o.Issuer <- getRequiredConfigValue builder "CoreIdent:Issuer"
            o.Audience <- getRequiredConfigValue builder "CoreIdent:Audience"
        ) |> ignore

        builder.Services.AddSigningKey(fun o ->
            o.UseSymmetric(getRequiredConfigValue builder "CoreIdent:DevSigningKey") |> ignore
        ) |> ignore

        //#if (usePasswordless)
        builder.Services.AddSingleton<IEmailSender, DevEmailSender>() |> ignore
        //#endif

        //#if (useEfCore)
        let connectionString =
            match builder.Configuration.["ConnectionStrings:CoreIdent"] with
            | null
            | "" -> "Data Source=coreident.db"
            | value -> value

        builder.Services.AddDbContext<CoreIdentDbContext>(fun options ->
            options.UseSqlite(connectionString) |> ignore
        ) |> ignore

        builder.Services.RemoveAll<IClientStore>() |> ignore
        builder.Services.RemoveAll<IScopeStore>() |> ignore
        builder.Services.RemoveAll<IRefreshTokenStore>() |> ignore
        builder.Services.RemoveAll<IAuthorizationCodeStore>() |> ignore
        builder.Services.RemoveAll<IUserGrantStore>() |> ignore
        builder.Services.RemoveAll<ITokenRevocationStore>() |> ignore
        builder.Services.RemoveAll<IUserStore>() |> ignore
        builder.Services.RemoveAll<IPasswordlessTokenStore>() |> ignore

        builder.Services.AddEntityFrameworkCoreStores() |> ignore
        //#endif

        let client =
            CoreIdentClient(
                ClientId = "example_client",
                ClientName = "Example Client",
                ClientType = ClientType.Confidential,
                AllowedGrantTypes = List<string>([ GrantTypes.ClientCredentials ]),
                AllowedScopes = List<string>([ StandardScopes.OpenId ])
            )

        builder.Services.AddInMemoryClients(
            seq { struct (client, "example-secret") }
        ) |> ignore

        let app = builder.Build()

        //#if (useEfCore)
        use scope = app.Services.CreateScope()
        let db = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>()
        db.Database.EnsureCreated() |> ignore

        if not (db.Scopes.Any()) then
            db.Scopes.AddRange(
                [|
                    ScopeEntity(
                        Name = StandardScopes.OpenId,
                        DisplayName = "OpenID",
                        Description = "Your user identifier",
                        Required = true,
                        Emphasize = false,
                        ShowInDiscoveryDocument = true,
                        UserClaimsJson = JsonSerializer.Serialize([| "sub" |])
                    )
                |]
            ) |> ignore
            db.SaveChanges() |> ignore

        if not (db.Clients.Any()) then
            db.Clients.Add(
                ClientEntity(
                    ClientId = "example_client",
                    ClientName = "Example Client",
                    ClientType = nameof ClientType.Confidential,
                    RedirectUrisJson = "[]",
                    PostLogoutRedirectUrisJson = "[]",
                    AllowedScopesJson = JsonSerializer.Serialize([| StandardScopes.OpenId |]),
                    AllowedGrantTypesJson = JsonSerializer.Serialize([| GrantTypes.ClientCredentials |]),
                    AccessTokenLifetimeSeconds = 900,
                    RefreshTokenLifetimeSeconds = 86400,
                    RequirePkce = false,
                    RequireConsent = false,
                    AllowOfflineAccess = false,
                    Enabled = true,
                    CreatedAt = DateTime.UtcNow
                )
            ) |> ignore
            db.SaveChanges() |> ignore
        //#endif

        app.MapCoreIdentEndpoints() |> ignore
        app.MapGet("/", RequestDelegate(fun ctx ->
             ctx.Response.WriteAsync("CoreIdent API is running")
         )) |> ignore

        app.Run()
        0
