# CoreIdent CLI Reference (1.0)

CoreIdent ships a .NET tool package that provides a `dotnet coreident` command.

## Install

```bash
dotnet tool install -g CoreIdent.Cli
```

## Usage

```bash
dotnet coreident --help
```

## Commands

### `init`

Scaffolds a minimal `appsettings.json` with a CoreIdent section and writes a development-only symmetric signing key. It also updates your target `.csproj` with CoreIdent package references.

```bash
dotnet coreident init --project /path/to/MyApp.csproj
```

Options:

- `--project <path>`
  - Path to the `.csproj` to modify.
  - If omitted, the current directory must contain exactly one `.csproj`.
- `--force`
  - Overwrite `appsettings.json` if it already exists.

### `keys generate`

Generates an RSA or ECDSA key pair in PEM format.

```bash
dotnet coreident keys generate rsa
```

```bash
dotnet coreident keys generate ecdsa
```

Options:

- `--out <path>`
  - If omitted, writes PEM to stdout.
  - If a directory, writes `<dir>/<rsa|ecdsa>.private.pem` and `<dir>/<rsa|ecdsa>.public.pem`.
  - If a file path, writes private key to `<path>` and public key to `<path>` with `.public.pem`.
- `--size <bits>` (RSA only)
  - Default: `2048`.

### `client add`

Interactive client registration helper. Generates:

- `client_id`
- (confidential only) `client_secret`
- A C# snippet you can paste into your seeding/registration code.

```bash
dotnet coreident client add
```

Non-interactive options:

- `--name <clientName>`
- `--type <public|confidential>`
- `--client-id <clientId>`
- `--redirect-uri <uri>`
- `--scopes "openid profile offline_access"`

Notes:

- This command outputs a snippet; it does not currently persist the client to a store.

### `migrate`

Applies EF Core schema creation for `CoreIdentDbContext`. Supports multiple database providers.

```bash
# SQLite (default)
dotnet coreident migrate --connection "Data Source=coreident.db"

# SQL Server
dotnet coreident migrate --provider sqlserver --connection "Server=localhost;Database=CoreIdent;Trusted_Connection=True;"

# PostgreSQL
dotnet coreident migrate --provider postgres --connection "Host=localhost;Database=coreident;Username=postgres;Password=secret"
```

Behavior:

- Attempts to apply EF migrations if present.
- If no migrations exist, it falls back to creating the schema directly.

Options:

- `--provider <sqlite|sqlserver|postgres>` (or `-p`)
  - Database provider to use. Default: `sqlite`.
  - Aliases: `mssql` for SQL Server, `postgresql` or `npgsql` for PostgreSQL.
- `--connection <connectionString>` (or `-c`)
  - Connection string for the target database.
