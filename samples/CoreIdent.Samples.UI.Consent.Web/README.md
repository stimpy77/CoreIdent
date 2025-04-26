# CoreIdent Sample: User Consent Web UI Client

This sample application demonstrates how a client application (built with ASP.NET Core Razor Pages) interacts with a CoreIdent server during the **OAuth 2.0 Authorization Code Flow**, specifically showcasing the **User Consent** step.

**Important:** This project is only the **Client Application**. It requires a separate, running instance of the **CoreIdent Server** to function.

## Purpose

*   To show how a client initiates the Authorization Code flow with PKCE.
*   To demonstrate the user being redirected to the CoreIdent server for authentication.
*   To illustrate the user being presented with the CoreIdent consent screen when the client requests specific `scope`s and requires consent.
*   To show how the user's consent decision (Allow/Deny) is handled and how the flow proceeds based on that decision.
*   To provide a basic example of handling the callback (`/signin-oidc`) from the CoreIdent server.

## Prerequisites

1.  **.NET SDK:** Ensure you have a compatible .NET SDK installed (check the `.csproj` file or the main CoreIdent documentation for the target framework, likely .NET 8 or 9+).
2.  **Running CoreIdent Server:** You need a running instance of the CoreIdent server project.
    *   Make sure the CoreIdent server is configured (e.g., in its `appsettings.json`) and has necessary data seeded (users, clients, scopes).
    *   Specifically, the CoreIdent server **must** have a client registered with the `ClientId` used by this sample (see Configuration below).
    *   The CoreIdent server should be accessible via HTTPS (e.g., `https://localhost:7100`).

## Configuration

1.  **CoreIdent Server URL:**
    *   By default, this sample assumes the CoreIdent server is running at `https://localhost:7100`.
    *   If your CoreIdent server runs on a different URL, update the `CoreIdentServerUrl` setting. You can do this via:
        *   `appsettings.Development.json` (Create this file if it doesn't exist)
        ```json
        {
          "CoreIdentServerUrl": "https://your-coreident-server-url"
        }
        ```
        *   Environment Variables: `CoreIdentServerUrl=https://your-coreident-server-url`
        *   User Secrets

2.  **Client Registration in CoreIdent Server:**
    *   This sample uses the following client details (defined in `Pages/Account/Login.cshtml.cs`):
        *   `ClientId`: `sample-ui-client`
        *   `RedirectUri`: The callback path `/signin-oidc` appended to this sample's base URL (e.g., `https://localhost:7200/signin-oidc` if this sample runs on port 7200).
        *   `AllowedScopes`: `openid profile email offline_access` (Ensure these scopes exist in the CoreIdent server).
        *   `AllowedGrantTypes`: `authorization_code`
        *   `RequirePkce`: `true`
        *   `RequireConsent`: **`true`** (This is crucial for demonstrating the consent flow).
    *   You **must** register a client with these exact details (especially `ClientId` and `RedirectUri`) in your running CoreIdent server's configuration or database (e.g., via seeding in its `Program.cs` or using an admin UI if available). The `RedirectUri` must match the URL where this sample application will be running.

## Running the Sample

1.  **Navigate to the sample directory:**
    ```bash
    cd samples/CoreIdent.Samples.UI.Consent.Web
    ```
2.  **Run the application:**
    ```bash
    dotnet run
    ```
3.  **Access the application:** Open your web browser and navigate to the URL provided by `dotnet run` (e.g., `https://localhost:7200`).

## Expected Flow

1.  You will be redirected to the sample application's local login page (`/Account/Login`), as Razor Pages are protected by default in this sample's setup.
2.  Clicking the conceptual "Login via CoreIdent" button (or simply accessing `/Account/Login` in this sample) will trigger the `OnGet` handler in `Login.cshtml.cs`.
3.  The sample app generates PKCE parameters (`code_verifier`, `code_challenge`), stores them temporarily (e.g., in cookies), and redirects your browser to the CoreIdent server's `/auth/authorize` endpoint with the necessary OIDC parameters (`client_id`, `redirect_uri`, `scope`, `response_type=code`, `code_challenge`, `state`, etc.).
4.  The CoreIdent server will prompt you to log in (if you aren't already logged in there).
5.  After successful login, because the client `sample-ui-client` is configured with `RequireConsent=true` in the CoreIdent server, the server will redirect you to its **Consent Page**.
6.  The Consent Page will display the name of the client application ("Sample UI Client" or similar, based on client registration) and the permissions (`scope`s like `profile`, `email`) it's requesting.
7.  You can choose to **Allow** or **Deny** consent.
    *   **If you Deny:** The CoreIdent server redirects back to this sample application's `RedirectUri` (`/signin-oidc`) with an `error=access_denied` parameter in the query string. The sample app should handle this gracefully (currently, it might just show an error or fail to log you in locally).
    *   **If you Allow:** The CoreIdent server stores your consent grant and redirects back to this sample application's `RedirectUri` (`/signin-oidc`) with an `authorization_code` and the `state` parameter.
8.  The callback handler (`/signin-oidc` - **Note:** This handler needs to be implemented in this sample, likely in `Login.cshtml.cs` or a dedicated callback page model) receives the authorization code.
9.  The callback handler should:
    *   Verify the `state` parameter matches the one stored earlier.
    *   Retrieve the `code_verifier` stored earlier.
    *   Make a backend POST request to the CoreIdent server's `/auth/token` endpoint, exchanging the `authorization_code` and `code_verifier` for tokens (access token, refresh token, ID token).
    *   (Optional) Validate the received ID token.
    *   (Optional) Use the access token to call a protected API or retrieve user info from the CoreIdent server's `/userinfo` endpoint.
    *   Establish a local session for the user in *this* sample application (e.g., using the cookie authentication configured in `Program.cs`).
    *   Redirect the user to a desired page within the sample app (e.g., the homepage).

**Note:** The current implementation in `Login.cshtml.cs` only initiates the flow. The callback handling (`/signin-oidc`) and subsequent token exchange logic need to be added to complete the end-to-end demonstration within this sample project. 