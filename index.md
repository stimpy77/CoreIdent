# CoreIdent Project Index

This document provides a comprehensive overview of the CoreIdent project structure, components, and their purposes. Use this index to quickly locate specific functionality and understand the organization of the codebase.

## Project Overview

CoreIdent is a .NET 10 OpenID Connect and OAuth 2.0 server implementation focused on security, developer experience, and modern authentication patterns including passkeys and passwordless authentication.

## Directory Structure

```
CoreIdent/
├── src/                                    # Source code libraries
│   ├── CoreIdent.Core/                     # Core library with interfaces, models, and services
│   ├── CoreIdent.Storage.EntityFrameworkCore/ # EF Core store implementations
│   ├── CoreIdent.Adapters.DelegatedUserStore/ # Adapter for existing user stores
│   ├── CoreIdent.Aspire/                   # .NET Aspire integration
│   ├── CoreIdent.Cli/                      # Command-line interface tool
│   ├── CoreIdent.OpenApi/                  # OpenAPI/Swagger documentation
│   ├── CoreIdent.Passkeys/                 # Passkey/WebAuthn support
│   ├── CoreIdent.Passkeys.AspNetIdentity/  # Passkey integration with ASP.NET Identity
│   ├── CoreIdent.Passwords.AspNetIdentity/ # Password integration with ASP.NET Identity
│   └── CoreIdent.Templates/                # dotnet new template pack
├── tests/                                  # Test projects
│   ├── CoreIdent.Core.Tests/               # Unit tests for core functionality
│   ├── CoreIdent.Integration.Tests/        # Integration tests
│   ├── CoreIdent.Testing/                  # Shared test infrastructure
│   ├── CoreIdent.TestHost/                 # Test server host
│   ├── CoreIdent.Cli.Tests/                # CLI tests
│   ├── CoreIdent.Templates.Tests/          # Template tests
│   └── CoreIdent.FSharp.Sample/            # F# sample tests
├── templates/                              # Project templates
│   ├── coreident-api/                      # Minimal API template
│   ├── coreident-api-fsharp/               # F# API template
│   └── coreident-server/                   # Full server template with consent UI
├── samples/                                # Sample applications
│   └── CoreIdent.FSharp.Sample/            # F# sample application
├── docs/                                   # Documentation
├── website/                                # Project website
└── Configuration files                     # .sln, .gitignore, build props, etc.
```

## Source Libraries (`src/`)

### CoreIdent.Core/
**Purpose**: Core library containing all fundamental interfaces, models, services, and endpoints.

**Key Components**:
- `Configuration/` - Options classes and validation
  - `CoreIdentOptions.cs` - Main configuration options
  - `CoreIdentKeyOptions.cs` - Signing key configuration
  - `PasswordlessOptions.cs` - Passwordless authentication settings
- `Endpoints/` - HTTP endpoint implementations
  - `AuthEndpoints.cs` - Authentication endpoints
  - `TokenEndpoints.cs` - Token issuance and validation
  - `PasswordlessEndpoints.cs` - Passwordless authentication
  - `DiscoveryEndpoints.cs` - OIDC discovery endpoints
  - `OAuthEndpoints.cs` - OAuth 2.0 endpoints
- `Services/` - Core business logic services
  - `ITokenService.cs` / `JwtTokenService.cs` - JWT token handling
  - `ISigningKeyProvider.cs` - Asymmetric key management
  - `IPasswordlessService.cs` - Passwordless authentication logic
  - `ICoreIdentMetrics.cs` - OpenTelemetry metrics
- `Stores/` - Data access interfaces and in-memory implementations
  - `IUserStore.cs` - User data access
  - `IClientStore.cs` - OAuth client management
  - `IRefreshTokenStore.cs` - Refresh token storage
  - `ITokenRevocationStore.cs` - Token revocation tracking
  - `IPasswordlessTokenStore.cs` - Passwordless token storage
- `Models/` - Domain models and DTOs
  - User, client, token models
  - Request/response DTOs
- `Extensions/` - Extension methods for DI and configuration
  - `ServiceCollectionExtensions.cs` - DI registration
  - `EndpointRouteBuilderExtensions.cs` - Endpoint mapping
  - `ClaimsPrincipalExtensions.cs` - Claims utilities (C# 14 extensions)

### CoreIdent.Storage.EntityFrameworkCore/
**Purpose**: Entity Framework Core implementations of core store interfaces.

**Key Components**:
- EF Core DbContext and entity configurations
- Database implementations of all store interfaces
- Migration support for SQL Server, PostgreSQL, SQLite

### CoreIdent.Adapters.DelegatedUserStore/
**Purpose**: Adapter pattern implementation for integrating with existing user stores.

**Key Components**:
- `DelegatedUserStore.cs` - Delegates user operations to existing stores
- `DelegatedPasswordHasher.cs` - Password hashing integration
- Configuration and validation for delegation scenarios

### CoreIdent.Aspire/
**Purpose**: .NET Aspire integration for cloud-native applications.

**Key Components**:
- Service defaults configuration
- Health checks integration
- Distributed application builder extensions
- Observability and telemetry integration

### CoreIdent.Cli/
**Purpose**: Command-line interface tool for CoreIdent management.

**Key Components**:
- `CliApp.cs` - CLI application entry point
- `PemKeyGenerator.cs` - Key generation utilities
- `CsprojEditor.cs` - Project file manipulation
- Commands for key management, configuration, and development

### CoreIdent.OpenApi/
**Purpose**: OpenAPI/Swagger documentation generation for endpoints.

**Key Components**:
- OpenAPI document generation
- Endpoint documentation
- Schema definitions for API contracts

### CoreIdent.Passkeys/
**Purpose**: Passkey (WebAuthn) authentication support.

**Key Components**:
- Passkey registration and authentication flows
- WebAuthn API integration
- Challenge generation and validation
- Passkey credential management

### CoreIdent.Passkeys.AspNetIdentity/
**Purpose**: Passkey integration with ASP.NET Identity.

**Key Components**:
- ASP.NET Identity user store integration
- Passkey credential storage for Identity users
- Seamless integration with existing Identity applications

### CoreIdent.Passwords.AspNetIdentity/
**Purpose**: Password authentication integration with ASP.NET Identity.

**Key Components**:
- Password hashing and validation
- Identity password policy integration
- Migration support for existing Identity applications

### CoreIdent.Templates/
**Purpose**: dotnet new template pack for project scaffolding.

**Key Components**:
- Template configuration and packaging
- Template parameter processing
- Integration with dotnet CLI

## Test Projects (`tests/`)

### CoreIdent.Core.Tests/
**Purpose**: Unit tests for core library functionality.

**Key Components**:
- Service layer unit tests
- Model validation tests
- Extension method tests
- Configuration validation tests

### CoreIdent.Integration.Tests/
**Purpose**: End-to-end integration tests.

**Key Components**:
- HTTP endpoint integration tests
- OAuth/OIDC flow tests
- Database integration tests
- Authentication flow testing

### CoreIdent.Testing/
**Purpose**: Shared test infrastructure and utilities.

**Key Components**:
- Test fixtures and base classes
- Fluent builders for test data
- Assertion extensions
- Mock utilities and helpers

### CoreIdent.TestHost/
**Purpose**: Test server host for integration testing.

**Key Components**:
- Minimal test application setup
- Test configuration
- Endpoint mapping for tests

### CoreIdent.Cli.Tests/
**Purpose**: CLI tool testing.

**Key Components**:
- Command-line interface tests
- Key generation tests
- Project manipulation tests

### CoreIdent.Templates.Tests/
**Purpose**: Template validation and testing.

**Key Components**:
- Template generation tests
- Parameter validation
- Output verification

## Templates (`templates/`)

### coreident-api/
**Purpose**: Minimal API project template.

**Key Components**:
- Basic CoreIdent API setup
- Minimal configuration
- Essential endpoints only

### coreident-api-fsharp/
**Purpose**: F# minimal API project template.

**Key Components**:
- F# language implementation
- Functional programming patterns
- F#-specific configuration

### coreident-server/
**Purpose**: Full-featured server template with UI.

**Key Components**:
- Complete CoreIdent server setup
- Consent UI implementation
- Administrative interfaces
- Full configuration examples

## Documentation (`docs/`)

### Key Documentation Files
- `Project_Overview.md` - High-level project vision and architecture
- `Technical_Plan.md` - Detailed technical specifications and implementation guidance
- `DEVPLAN.md` - Task-level implementation checklist and progress tracking
- `Developer_Guide.md` - Integration and usage guide for developers
- `README_Detailed.md` - Comprehensive feature documentation
- `Passkeys.md` - Passkey authentication setup and configuration
- `Aspire_Integration.md` - .NET Aspire integration guide
- `CLI_Reference.md` - Command-line tool reference
- `FSharp_Guide.md` - F# specific guidance and examples

## Configuration Files

### Root Level Files
- `CoreIdent.sln` - Solution file
- `Directory.Build.props` - MSBuild properties for all projects
- `Directory.Build.targets` - MSBuild targets for all projects
- `.gitignore` - Git ignore patterns
- `README.md` - Project README
- `LICENSE` - License file
- `CHANGELOG.md` - Version history
- `CONTRIBUTING.md` - Contribution guidelines
- `MIGRATION.md` - Migration guide for version upgrades

## Website (`website/`)

**Purpose**: Project website and documentation site.

**Key Components**:
- `index.html` - Main landing page
- `features.html` - Feature overview
- `style.css` - Website styling
- `assets/` - Static assets (logos, images)

## Key Architectural Patterns

### Interface-Driven Design
All major services implement interfaces for testability and extensibility:
- Store interfaces for data access
- Service interfaces for business logic
- Configuration interfaces for options

### Dependency Injection
Heavy use of .NET DI container with:
- `TryAdd` methods for override capability
- Options pattern for configuration
- Service lifetime management

### Security-First Approach
- Asymmetric key support (RS256/ES256) for production
- Token revocation and introspection (RFC 7009/7662)
- Passkey/WebAuthn support
- Passwordless authentication options

### Modern .NET 10 Features
- C# 14 extension members for ClaimsPrincipal
- Minimal APIs for endpoint implementation
- Built-in OpenTelemetry metrics
- Enhanced passkey support

## Development Workflow

### Getting Started
1. Start with `docs/Project_Overview.md` for high-level understanding
2. Review `docs/Technical_Plan.md` for detailed specifications
3. Use `docs/DEVPLAN.md` to track implementation progress
4. Follow `CLAUDE.md` for development guidelines and standards

### Testing Strategy
- Unit tests for all services and utilities
- Integration tests for HTTP endpoints
- Shared test infrastructure via `CoreIdent.Testing`
- Coverage requirements (>= 90% for CoreIdent.Core)

### Build and Deployment
- .NET 10 target framework
- MSBuild-based build system
- Package management via NuGet
- Container support via .NET Aspire

## Quick Reference

### Common Tasks
- **Add authentication**: Use `src/CoreIdent.Core/Extensions/ServiceCollectionExtensions.cs`
- **Configure endpoints**: Use `src/CoreIdent.Core/Extensions/EndpointRouteBuilderExtensions.cs`
- **Add storage**: Implement store interfaces or use EF Core implementation
- **Add metrics**: Use `src/CoreIdent.Core/Services/ICoreIdentMetrics.cs`
- **CLI operations**: Use `src/CoreIdent.Cli/` tools

### Important Files
- `src/CoreIdent.Core/Configuration/CoreIdentOptions.cs` - Main configuration
- `src/CoreIdent.Core/Services/JwtTokenService.cs` - Token handling
- `src/CoreIdent.Core/Endpoints/` - All HTTP endpoints
- `docs/DEVPLAN.md` - Implementation status and roadmap

This index should help you quickly locate the components you need for development, testing, or integration with CoreIdent.
