using CoreIdent.Core.Models;
using CoreIdent.Core.Stores;
using CoreIdent.Storage.EntityFrameworkCore;
using CoreIdent.Storage.EntityFrameworkCore.Stores;
using Microsoft.EntityFrameworkCore;
using Moq;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CoreIdent.Core.Tests.Stores;

public class EfScopeStoreUnitTests
{
    private readonly Mock<IScopeStore> _mockScopeStore;
    private readonly List<CoreIdentScope> _scopes;

    public EfScopeStoreUnitTests()
    {
        // Setup test data
        _scopes = new List<CoreIdentScope>
        {
            new CoreIdentScope { Name = "scope1" },
            new CoreIdentScope { Name = "scope2" },
            new CoreIdentScope { Name = "scope3" }
        };

        // Create a mock of the IScopeStore interface instead of using the concrete implementation
        _mockScopeStore = new Mock<IScopeStore>();

        // Setup the GetAllScopesAsync method to return our test scopes
        _mockScopeStore
            .Setup(m => m.GetAllScopesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_scopes.Take(2).ToList());

        // Setup the FindScopesByNameAsync method
        _mockScopeStore
            .Setup(m => m.FindScopesByNameAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IEnumerable<string> names, CancellationToken _) =>
                _scopes.Where(s => names.Contains(s.Name)).ToList());
    }

    [Fact]
    public async Task GetAllScopesAsync_ReturnsScopesFromContext()
    {
        // Act
        var result = await _mockScopeStore.Object.GetAllScopesAsync(CancellationToken.None);

        // Assert
        result.ShouldNotBeNull();
        result.Count().ShouldBe(2);
        result.Select(s => s.Name).ShouldBe(new[] { "scope1", "scope2" });
    }

    [Fact]
    public async Task FindScopesByNameAsync_ReturnsMatchingScopesFromContext()
    {
        // Arrange
        var namesToFind = new List<string> { "scope1", "scope3", "scope4" };

        // Act
        var result = await _mockScopeStore.Object.FindScopesByNameAsync(namesToFind, CancellationToken.None);

        // Assert
        result.ShouldNotBeNull();
        result.Count().ShouldBe(2);
        result.Select(s => s.Name).ShouldBe(new[] { "scope1", "scope3" }, ignoreOrder: true);
    }
} 