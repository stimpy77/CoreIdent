using CoreIdent.Core.Configuration;
using System;
using Xunit;

namespace CoreIdent.Core.Tests.Configuration
{
    public class CoreIdentRouteOptionsTests
    {
        [Theory]
        [InlineData("/auth", "./token", "/auth/token")]
        [InlineData("/auth", "../token", "/token")]
        [InlineData("/auth/", "../token", "/token")]
        [InlineData("/auth/", "./token", "/auth/token")]
        [InlineData("/auth/", "token", "/auth/token")]
        [InlineData("/", "../token", "/token")]
        public void Combine_NormalizesDotSegments(string basePath, string relativePath, string expected)
        {
            var options = new CoreIdentRouteOptions { BasePath = basePath };
            var result = options.Combine(relativePath);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("/me", true)] // Default, root-relative
        [InlineData("me", false)] // Base-path relative
        [InlineData("/api/v1/user", true)] // Root-relative
        [InlineData("users/profile", false)] // Base-path relative
        [InlineData(" /me", true)] // Trim leading space, root-relative
        [InlineData("me/ ", false)] // Trim trailing space, base-path relative
        public void UserProfilePath_IsRootRelative_BasedOnLeadingSlash(string userProfilePath, bool expectedRootRelative)
        {
            // This test conceptually checks the logic that would be used in MapUserProfileEndpoints
            var isRootRelative = userProfilePath.Trim().StartsWith("/");
            Assert.Equal(expectedRootRelative, isRootRelative);
        }

        [Theory]
        [InlineData("/auth", "/me", "/me")] // Root relative ignores base path
        [InlineData("/auth", "me", "/auth/me")] // Base path relative joins with base path
        [InlineData("/identity", "me", "/identity/me")]
        [InlineData("/", "me", "/me")] // Base path of root
        [InlineData("/auth", "/api/profile", "/api/profile")] // Different root path
        public void UserProfilePath_ExpectedMappedPath(string basePath, string userProfilePath, string expectedPath)
        {
            // This test simulates the path construction logic
            var path = userProfilePath.Trim();
            string finalPath;
            if (path.StartsWith("/"))
            {
                finalPath = "/" + path.TrimStart('/');
            }
            else
            {
                // Simulate combining with base path (simple join for test)
                finalPath = basePath.TrimEnd('/') + "/" + path.TrimStart('/');
                 if (finalPath.Length > 1 && finalPath.EndsWith("/"))
                 {
                     finalPath = finalPath.TrimEnd('/');
                 }
                 if (!finalPath.StartsWith("/")) // Ensure leading slash if base was empty
                 {
                    finalPath = "/" + finalPath;
                 }
            }
            Assert.Equal(expectedPath, finalPath);
        }
    }
}
