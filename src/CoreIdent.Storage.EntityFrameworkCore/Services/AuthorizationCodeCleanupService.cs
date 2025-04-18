using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Storage.EntityFrameworkCore.Services;

/// <summary>
/// Background service that periodically removes expired authorization codes from the database.
/// </summary>
public class AuthorizationCodeCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AuthorizationCodeCleanupService> _logger;
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromHours(1); // Check every hour

    // TODO: Make interval configurable via options

    public AuthorizationCodeCleanupService(IServiceProvider serviceProvider, ILogger<AuthorizationCodeCleanupService> logger)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Authorization Code Cleanup Service starting.");

        stoppingToken.Register(() => _logger.LogInformation("Authorization Code Cleanup Service is stopping."));

        while (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("Authorization Code Cleanup Service is running background task.");

            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<CoreIdentDbContext>();
                    var now = DateTime.UtcNow;

                    _logger.LogDebug("Querying for expired authorization codes older than {UtcNow}.", now);

                    // Note: EF Core 6+ supports ExecuteDeleteAsync for batch deletes
                    // For broader compatibility, query and remove.
                    var expiredCodes = await dbContext.AuthorizationCodes
                        .Where(ac => ac.ExpirationTime < now)
                        .ToListAsync(stoppingToken);

                    if (expiredCodes.Count > 0)
                    {
                        _logger.LogInformation("Found {Count} expired authorization codes to remove.", expiredCodes.Count);
                        dbContext.AuthorizationCodes.RemoveRange(expiredCodes);
                        await dbContext.SaveChangesAsync(stoppingToken);
                        _logger.LogInformation("Expired authorization codes removed successfully.");
                    }
                    else
                    {
                        _logger.LogDebug("No expired authorization codes found.");
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Authorization Code Cleanup Service stopping due to cancellation request.");
                break; // Exit loop if cancellation is requested
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during authorization code cleanup.");
                // Consider more specific error handling or recovery logic
            }

            try
            {
                // Wait for the next interval, respecting the cancellation token
                await Task.Delay(_cleanupInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Authorization Code Cleanup Service delay interrupted by cancellation.");
                break; // Exit loop if cancellation is requested during delay
            }
        }

        _logger.LogInformation("Authorization Code Cleanup Service finished.");
    }
} 