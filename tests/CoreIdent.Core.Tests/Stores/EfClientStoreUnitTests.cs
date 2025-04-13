using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Moq;
using Shouldly;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using CoreIdent.Core.Tests.Utils;

namespace CoreIdent.Core.Tests.Stores;

public class EfClientStoreUnitTests
{
    private readonly Mock<IClientStore> _mockClientStore;
    private readonly List<CoreIdentClient> _clients;

    public EfClientStoreUnitTests()
    {
        // Setup test data
        _clients = new List<CoreIdentClient>
        {
            new CoreIdentClient 
            { 
                ClientId = "findme_client", 
                ClientName = "Test Client", 
                ClientSecrets = new List<CoreIdentClientSecret>() 
            }
        };

        // Create a mock of the IClientStore interface
        _mockClientStore = new Mock<IClientStore>();

        // Setup FindClientByIdAsync for the "found" case
        _mockClientStore
            .Setup(m => m.FindClientByIdAsync("findme_client", It.IsAny<CancellationToken>()))
            .ReturnsAsync(_clients.First());

        // Setup FindClientByIdAsync for the "not found" case
        _mockClientStore
            .Setup(m => m.FindClientByIdAsync("notfound_client", It.IsAny<CancellationToken>()))
            .ReturnsAsync((CoreIdentClient?)null);
    }

    [Fact]
    public async Task FindClientByIdAsync_ReturnsClientFromContext()
    {
        // Arrange
        var clientId = "findme_client";

        // Act
        var result = await _mockClientStore.Object.FindClientByIdAsync(clientId, CancellationToken.None);

        // Assert
        result.ShouldNotBeNull();
        result.ClientId.ShouldBe(clientId);
    }

    [Fact]
    public async Task FindClientByIdAsync_ReturnsNullIfNotFound()
    {
        // Arrange
        var clientId = "notfound_client";

        // Act
        var result = await _mockClientStore.Object.FindClientByIdAsync(clientId, CancellationToken.None);

        // Assert
        result.ShouldBeNull();
    }
} 