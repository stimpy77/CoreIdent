# CoreIdent 0.4: F# Guide

CoreIdent is designed to be usable from **F#** as a first-class .NET language.

## Quick start (F#)

The equivalent of the C# quick start is:

- configure CoreIdent services
- configure a signing key provider
- map endpoints via `MapCoreIdentEndpoints()`

## Minimal host example

See `samples/CoreIdent.FSharp.Sample` for a small, buildable example using Giraffe.

## Common patterns

- `AddCoreIdent()` overloads accept delegates, which are naturally consumable from F#.
- Store/service interfaces use `Task` return types (F# `task {}` compatible).
- Prefer options-based configuration over `out` parameters.

## Notes

- The F# sample uses `UseSymmetric(...)` for simplicity. This is **development-only**.
- For production, prefer RSA/ECDSA via `UseRsa(...)` / `UseEcdsa(...)`.
