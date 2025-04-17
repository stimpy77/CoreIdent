using CoreIdent.Core.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Services;

/// <summary>
/// Background service that periodically cleans up expired and consumed refresh tokens
/// based on the configured retention policies.
/// </summary>
public class RefreshTokenCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<CoreIdentOptions> _options;
    private readonly ILogger<RefreshTokenCleanupService> _logger;
    private readonly TimeSpan _cleanupInterval;

    /// <summary>
    /// Initializes a new instance of the <see cref="RefreshTokenCleanupService"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider used to create scoped services.</param>
    /// <param name="options">The CoreIdent options.</param>
    /// <param name="logger">The logger instance.</param>
    public RefreshTokenCleanupService(
        IServiceProvider serviceProvider,
        IOptions<CoreIdentOptions> options,
        ILogger<RefreshTokenCleanupService> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // Default cleanup interval is once per hour
        // In a production system, this could be made configurable
        _cleanupInterval = TimeSpan.FromHours(1);
    }

    /// <summary>
    /// Executes the token cleanup process at scheduled intervals.
    /// </summary>
    /// <param name="stoppingToken">The cancellation token that can be used to stop the service.</param>
    /// <returns>A task representing the background operation.</returns>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Refresh token cleanup service is starting");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupTokensAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "An error occurred during refresh token cleanup");
            }

            // Wait for the next scheduled cleanup
            await Task.Delay(_cleanupInterval, stoppingToken);
        }
    }

    /// <summary>
    /// Performs the actual token cleanup operation.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the cleanup operation.</returns>
    private async Task CleanupTokensAsync(CancellationToken cancellationToken)
    {
        // Create a scope to resolve the DbContext
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
        
        var utcNow = DateTime.UtcNow;
        var options = _options.Value;
        int expiredTokensRemoved = 0;
        int consumedTokensRemoved = 0;

        try
        {
            // 1. Clean up expired tokens (tokens that have passed their expiration time)
            var expiredTokens = await dbContext.RefreshTokens
                .Where(t => t.ExpirationTime < utcNow)
                .ToListAsync(cancellationToken);

            if (expiredTokens.Any())
            {
                dbContext.RefreshTokens.RemoveRange(expiredTokens);
                expiredTokensRemoved = expiredTokens.Count;
            }

            // 2. Clean up consumed tokens based on retention period policy
            if (options.ConsumedTokenRetentionPeriod.HasValue)
            {
                var retentionCutoff = utcNow.Subtract(options.ConsumedTokenRetentionPeriod.Value);
                
                var oldConsumedTokens = await dbContext.RefreshTokens
                    .Where(t => t.ConsumedTime != null && t.ConsumedTime < retentionCutoff)
                    .ToListAsync(cancellationToken);

                if (oldConsumedTokens.Any())
                {
                    dbContext.RefreshTokens.RemoveRange(oldConsumedTokens);
                    consumedTokensRemoved = oldConsumedTokens.Count;
                }
            }

            // Save changes if we have any tokens to remove
            if (expiredTokensRemoved > 0 || consumedTokensRemoved > 0)
            {
                await dbContext.SaveChangesAsync(cancellationToken);
                _logger.LogInformation(
                    "Cleaned up refresh tokens: {ExpiredCount} expired, {ConsumedCount} consumed tokens removed",
                    expiredTokensRemoved, consumedTokensRemoved);
            }
            else
            {
                _logger.LogDebug("No refresh tokens needed cleanup");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up refresh tokens");
            throw; // Rethrow to be caught by the outer try-catch
        }
    }
} 