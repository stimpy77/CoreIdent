using CoreIdent.Core.Configuration;
using CoreIdent.Core.Stores;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreIdent.Core.Services;

public sealed class AuthorizationCodeCleanupHostedService : BackgroundService
{
    private readonly IAuthorizationCodeStore _store;
    private readonly IOptions<CoreIdentAuthorizationCodeOptions> _options;
    private readonly ILogger<AuthorizationCodeCleanupHostedService> _logger;

    public AuthorizationCodeCleanupHostedService(
        IAuthorizationCodeStore store,
        IOptions<CoreIdentAuthorizationCodeOptions> options,
        ILogger<AuthorizationCodeCleanupHostedService> logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_options.Value.EnableCleanupHostedService)
                {
                    await _store.CleanupExpiredAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up expired authorization codes.");
            }

            try
            {
                await Task.Delay(_options.Value.CleanupInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
        }
    }
}
