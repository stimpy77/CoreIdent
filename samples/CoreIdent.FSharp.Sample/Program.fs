open System
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Giraffe
open CoreIdent.Core.Extensions

let webApp : HttpHandler =
    choose [
        route "/" >=> text "CoreIdent F# sample is running"
    ]

let builder = WebApplication.CreateBuilder()

builder.Services.AddCoreIdent() |> ignore

builder.Services.AddSigningKey(fun o ->
    o.UseSymmetric("this-is-a-dev-only-secret-please-change") |> ignore
) |> ignore

builder.Services.AddGiraffe() |> ignore

let app = builder.Build()

app.MapCoreIdentEndpoints() |> ignore
app.UseGiraffe(webApp)

app.Run()
