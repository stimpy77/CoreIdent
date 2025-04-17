using CoreIdent.Core.Models;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Stores;

/// <summary>
/// Provides an abstraction for storing and retrieving authorization codes.
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Stores the authorization code details.
    /// </summary>
    /// <param name="code">The authorization code details to store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task StoreAuthorizationCodeAsync(AuthorizationCode code, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the authorization code details associated with the provided code handle.
    /// It is expected that the implementation returns null if the code is not found.
    /// </summary>
    /// <param name="codeHandle">The handle of the authorization code to retrieve.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// A task that represents the asynchronous operation, containing the <see cref="AuthorizationCode"/>
    /// details if found; otherwise, null.
    /// </returns>
    Task<AuthorizationCode?> GetAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the authorization code associated with the provided code handle.
    /// This is typically called after the code has been successfully redeemed.
    /// </summary>
    /// <param name="codeHandle">The handle of the authorization code to remove.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task RemoveAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken);
} 