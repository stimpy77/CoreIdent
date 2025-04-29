using CoreIdent.Core.Models;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace CoreIdent.Core.Stores.InMemory;

public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new();
    private readonly ILogger<InMemoryAuthorizationCodeStore> _logger;

    public InMemoryAuthorizationCodeStore(ILogger<InMemoryAuthorizationCodeStore> logger)
    {
        _logger = logger;
    }

    public Task<StoreResult> StoreAuthorizationCodeAsync(AuthorizationCode code, CancellationToken cancellationToken)
    {
        // Use TryAdd for better concurrency handling, although conflict unlikely with truly random codes
        if (_codes.TryAdd(code.CodeHandle, code))
        {
            _logger.LogDebug("Stored authorization code: {CodeHandle}, Expires: {Expiry}", code.CodeHandle, code.ExpirationTime);
            // Start a background task to remove expired code (simple cleanup)
            _ = Task.Delay(code.ExpirationTime - DateTime.UtcNow + TimeSpan.FromSeconds(5), cancellationToken)
                .ContinueWith(_ =>
                {
                    if (_codes.TryRemove(code.CodeHandle, out var removedCode) && removedCode.ExpirationTime <= DateTime.UtcNow)
                    {
                        _logger.LogDebug("Removed expired authorization code: {CodeHandle}", code.CodeHandle);
                    }
                }, CancellationToken.None); // Use CancellationToken.None for the cleanup task
            return Task.FromResult(StoreResult.Success);
        }
        else
        {
            // This case should be rare with good random code generation
            _logger.LogWarning("Conflict storing authorization code in memory store: {CodeHandle}", code.CodeHandle);
            return Task.FromResult(StoreResult.Conflict);
        }
    }

    public Task<AuthorizationCode?> GetAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        _codes.TryGetValue(codeHandle, out var code);
        if (code != null && code.ExpirationTime < DateTime.UtcNow)
        {
            _logger.LogDebug("Attempted to retrieve expired code: {CodeHandle}", codeHandle);
            _codes.TryRemove(codeHandle, out _); // Remove expired on retrieval attempt
            return Task.FromResult<AuthorizationCode?>(null);
        }
        _logger.LogDebug("Retrieved authorization code: {CodeHandle} (Found: {Found})", codeHandle, code != null);
        return Task.FromResult(code);
    }

    public Task RemoveAuthorizationCodeAsync(string codeHandle, CancellationToken cancellationToken)
    {
        if (_codes.TryRemove(codeHandle, out _))
        {
            _logger.LogDebug("Removed authorization code: {CodeHandle}", codeHandle);
        }
        else
        {
            _logger.LogDebug("Attempted to remove non-existent code: {CodeHandle}", codeHandle);
        }
        return Task.CompletedTask;
    }
}