using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Entity Framework Core implementation for storing authorization codes.
/// </summary>
public class EfAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly CoreIdentDbContext _context;
    private readonly ILogger<EfAuthorizationCodeStore> _logger;

    public EfAuthorizationCodeStore(CoreIdentDbContext context, ILogger<EfAuthorizationCodeStore> logger)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task StoreAuthorizationCodeAsync(AuthorizationCode code, CancellationToken cancellationToken)
    {
        if (code == null) throw new ArgumentNullException(nameof(code));
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogDebug("Storing authorization code for ClientId: {ClientId}, SubjectId: {SubjectId}", code.ClientId, code.SubjectId);
        _context.AuthorizationCodes.Add(code);
        try
        {
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error storing authorization code for ClientId: {ClientId}", code.ClientId);
            // Consider specific handling for unique constraint violations if CodeHandle hashing is added
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<AuthorizationCode?> GetAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(codeHandle)) throw new ArgumentNullException(nameof(codeHandle));
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogDebug("Retrieving authorization code with handle starting: {CodeHandlePrefix}...", codeHandle.Length > 4 ? codeHandle.Substring(0, 4) : codeHandle);

        var now = DateTime.UtcNow;
        var code = await _context.AuthorizationCodes
            .AsNoTracking() // No need to track changes when just retrieving
            .FirstOrDefaultAsync(ac => ac.CodeHandle == codeHandle, cancellationToken);

        if (code == null)
        {
            _logger.LogDebug("Authorization code not found.");
            return null;
        }

        if (code.ExpirationTime <= now)
        {
            _logger.LogWarning("Retrieved authorization code is expired for ClientId: {ClientId}, SubjectId: {SubjectId}. Expiration: {ExpirationTime}",
                code.ClientId, code.SubjectId, code.ExpirationTime);
            // Optionally remove expired code here, though cleanup service is preferred
            // await RemoveAuthorizationCodeAsync(codeHandle, cancellationToken);
            return null; // Treat expired codes as not found
        }

        _logger.LogDebug("Authorization code found for ClientId: {ClientId}, SubjectId: {SubjectId}", code.ClientId, code.SubjectId);
        return code;
    }

    /// <inheritdoc />
    public async Task RemoveAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(codeHandle)) throw new ArgumentNullException(nameof(codeHandle));
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogDebug("Removing authorization code with handle starting: {CodeHandlePrefix}...", codeHandle.Length > 4 ? codeHandle.Substring(0, 4) : codeHandle);

        // Use FindAsync instead of FirstOrDefaultAsync for better testability and performance
        var code = await _context.AuthorizationCodes.FindAsync(new object[] { codeHandle }, cancellationToken);

        if (code != null)
        {
            _context.AuthorizationCodes.Remove(code);
            try
            {
                await _context.SaveChangesAsync(cancellationToken);
                _logger.LogDebug("Authorization code removed successfully.");
            }
            catch (DbUpdateConcurrencyException ex)
            {
                // Handle potential concurrency issues if another process already removed it
                _logger.LogWarning(ex, "Concurrency conflict removing authorization code with handle starting: {CodeHandlePrefix}", codeHandle.Length > 4 ? codeHandle.Substring(0, 4) : codeHandle);
                // Swallow or re-throw based on desired behavior
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error removing authorization code with handle starting: {CodeHandlePrefix}", codeHandle.Length > 4 ? codeHandle.Substring(0, 4) : codeHandle);
                throw;
            }
        }
        else
        {
            _logger.LogDebug("Authorization code not found during removal attempt.");
        }
    }
} 