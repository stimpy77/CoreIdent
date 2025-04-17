using System;
using System.Security.Cryptography;
using System.Text;

namespace CoreIdent.Core.Services;

/// <summary>
/// Provides methods for securely hashing token handles before storage.
/// </summary>
public static class TokenHasher
{
    /// <summary>
    /// Hashes a refresh token handle using SHA-256 and the provided salt.
    /// </summary>
    /// <param name="tokenHandle">The raw token handle to hash.</param>
    /// <param name="salt">Salt value to add entropy (e.g., userId + clientId).</param>
    /// <returns>A Base64-encoded hash of the token handle.</returns>
    public static string HashToken(string tokenHandle, string salt)
    {
        if (string.IsNullOrEmpty(tokenHandle))
            throw new ArgumentNullException(nameof(tokenHandle));
        
        if (salt == null) // Empty salt is allowed, but null is not
            throw new ArgumentNullException(nameof(salt));

        // Combine token and salt
        var tokenWithSalt = tokenHandle + salt;
        
        // Compute SHA-256 hash
        byte[] hashBytes;
        using (var sha256 = SHA256.Create())
        {
            hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenWithSalt));
        }
        
        // Convert to URL-safe Base64 string
        return Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
    
    /// <summary>
    /// Hashes a refresh token handle using SHA-256 with a salt composed of user ID and client ID.
    /// This follows the convention over configuration principle by using a standard salting approach.
    /// </summary>
    /// <param name="tokenHandle">The raw token handle to hash.</param>
    /// <param name="userId">The user ID to use as part of the salt.</param>
    /// <param name="clientId">The client ID to use as part of the salt.</param>
    /// <returns>A Base64-encoded hash of the token handle.</returns>
    public static string HashToken(string tokenHandle, string userId, string clientId)
    {
        if (string.IsNullOrEmpty(userId))
            throw new ArgumentNullException(nameof(userId));
        
        if (string.IsNullOrEmpty(clientId))
            throw new ArgumentNullException(nameof(clientId));
            
        // Create a deterministic salt from user and client IDs
        var salt = $"{userId}:{clientId}";
        
        return HashToken(tokenHandle, salt);
    }
    
    /// <summary>
    /// Verifies if a provided token handle matches a stored hash when hashed with the same salt.
    /// </summary>
    /// <param name="tokenHandle">The raw token handle to verify.</param>
    /// <param name="storedHash">The previously stored hash to compare against.</param>
    /// <param name="salt">The salt used when creating the original hash.</param>
    /// <returns>True if the token handle matches the stored hash, false otherwise.</returns>
    public static bool VerifyToken(string tokenHandle, string storedHash, string salt)
    {
        if (string.IsNullOrEmpty(tokenHandle))
            throw new ArgumentNullException(nameof(tokenHandle));
            
        if (string.IsNullOrEmpty(storedHash))
            throw new ArgumentNullException(nameof(storedHash));
            
        if (salt == null)
            throw new ArgumentNullException(nameof(salt));
            
        // Hash the provided token with the same salt
        var computedHash = HashToken(tokenHandle, salt);
        
        // Use a constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computedHash),
            Encoding.UTF8.GetBytes(storedHash));
    }
    
    /// <summary>
    /// Verifies if a provided token handle matches a stored hash when hashed with a salt composed of user ID and client ID.
    /// </summary>
    /// <param name="tokenHandle">The raw token handle to verify.</param>
    /// <param name="storedHash">The previously stored hash to compare against.</param>
    /// <param name="userId">The user ID used as part of the salt.</param>
    /// <param name="clientId">The client ID used as part of the salt.</param>
    /// <returns>True if the token handle matches the stored hash, false otherwise.</returns>
    public static bool VerifyToken(string tokenHandle, string storedHash, string userId, string clientId)
    {
        if (string.IsNullOrEmpty(userId))
            throw new ArgumentNullException(nameof(userId));
            
        if (string.IsNullOrEmpty(clientId))
            throw new ArgumentNullException(nameof(clientId));
            
        var salt = $"{userId}:{clientId}";
        
        return VerifyToken(tokenHandle, storedHash, salt);
    }
} 