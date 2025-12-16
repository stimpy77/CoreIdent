namespace CoreIdentApi

open System
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Http
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open CoreIdent.Core.Extensions

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

        let app = builder.Build()

        app.MapCoreIdentEndpoints() |> ignore
        app.MapGet("/", RequestDelegate(fun ctx ->
             ctx.Response.WriteAsync("CoreIdent API is running")
         )) |> ignore

        app.Run()
        0
