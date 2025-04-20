using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Models;
using CoreIdent.Core.Services;
using System.Collections.Generic;

namespace CoreIdent.Core.Tests.Services
{
    public class TokenServiceUnitTests
    {
        [Fact]
        public async Task GenerateAccessTokenAsync_Returns_Token()
        {
            // Arrange
            var tokenService = new Mock<ITokenService>();
            tokenService.Setup(x => x.GenerateAccessTokenAsync(It.IsAny<CoreIdentUser>(), It.IsAny<IEnumerable<string>?>())).ReturnsAsync("access-token-xyz");

            // Act
            var token = await tokenService.Object.GenerateAccessTokenAsync(new CoreIdentUser { Id = "user1" });

            // Assert
            token.ShouldBe("access-token-xyz");
        }

        [Fact]
        public async Task GenerateAndStoreRefreshTokenAsync_Returns_RefreshToken()
        {
            // Arrange
            var tokenService = new Mock<ITokenService>();
            tokenService.Setup(x => x.GenerateAndStoreRefreshTokenAsync(It.IsAny<CoreIdentUser>(), "client1", It.IsAny<CoreIdentRefreshToken>())).ReturnsAsync("refresh-token-abc");

            // Act
#pragma warning disable CS8625
            var refreshToken = await tokenService.Object.GenerateAndStoreRefreshTokenAsync(new CoreIdentUser { Id = "user1" }, "client1", (CoreIdentRefreshToken?)null);
#pragma warning restore CS8625

            // Assert
            refreshToken.ShouldBe("refresh-token-abc");
        }
    }
}
