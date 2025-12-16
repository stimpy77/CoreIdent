namespace CoreIdentApi

open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open CoreIdent.Core.Extensions

module Program =

    [<EntryPoint>]
    let main args =
        let builder = WebApplication.CreateBuilder(args)

        builder.Services.AddCoreIdent(fun o ->
            o.Issuer <- builder.Configuration.["CoreIdent:Issuer"]
            o.Audience <- builder.Configuration.["CoreIdent:Audience"]
        ) |> ignore

        builder.Services.AddSigningKey(fun o ->
            o.UseSymmetric(builder.Configuration.["CoreIdent:DevSigningKey"]) |> ignore
        ) |> ignore

        let app = builder.Build()

        app.MapCoreIdentEndpoints() |> ignore
        app.MapGet("/", fun () -> "CoreIdent API is running") |> ignore

        app.Run()
        0
