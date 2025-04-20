using System.Threading.Tasks;
using Xunit;
using Moq;
using Shouldly;
using CoreIdent.Core.Stores;
using System.Collections.Generic;

namespace CoreIdent.Core.Tests.Services
{
    public class ConsentProcessingServiceTests
    {
        [Fact]
        public async Task StoreUserGrantAsync_Stores_Consent()
        {
            // Arrange
            var consentStore = new Mock<IUserGrantStore>();
            consentStore.Setup(x => x.StoreUserGrantAsync("user1", "client1", It.IsAny<IEnumerable<string>>(), default)).Returns(Task.CompletedTask);

            // Act
            await consentStore.Object.StoreUserGrantAsync("user1", "client1", new[] { "openid" }, default);

            // Assert
            consentStore.Verify(x => x.StoreUserGrantAsync("user1", "client1", It.IsAny<IEnumerable<string>>(), default), Times.Once);
        }

        [Fact]
        public async Task HasUserGrantedConsentAsync_Returns_True_When_Consent_Exists()
        {
            // Arrange
            var consentStore = new Mock<IUserGrantStore>();
            consentStore.Setup(x => x.HasUserGrantedConsentAsync("user1", "client1", It.IsAny<IEnumerable<string>>(), default)).ReturnsAsync(true);

            // Act
            var hasConsent = await consentStore.Object.HasUserGrantedConsentAsync("user1", "client1", new[] { "openid" }, default);

            // Assert
            hasConsent.ShouldBeTrue();
        }
    }
}
