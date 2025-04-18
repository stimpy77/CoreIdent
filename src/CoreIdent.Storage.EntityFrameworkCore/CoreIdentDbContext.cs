using CoreIdent.Core.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace CoreIdent.Storage.EntityFrameworkCore;

/// <summary>
/// EF Core DbContext for CoreIdent data persistence.
/// </summary>
public class CoreIdentDbContext : DbContext
{
    // --- User Related DbSets ---
    public virtual DbSet<CoreIdentUser> Users { get; set; } = default!;
    public virtual DbSet<CoreIdentUserClaim> UserClaims { get; set; } = default!;

    // --- Token Related DbSets ---
    public virtual DbSet<CoreIdentRefreshToken> RefreshTokens { get; set; } = default!;

    // --- Client/Scope Related DbSets ---
    public virtual DbSet<CoreIdentClient> Clients { get; set; } = default!;
    public virtual DbSet<CoreIdentClientSecret> ClientSecrets { get; set; } = default!;
    public virtual DbSet<CoreIdentScope> Scopes { get; set; } = default!;
    public virtual DbSet<CoreIdentScopeClaim> ScopeClaims { get; set; } = default!;

    // --- Authorization Code DbSet ---
    public virtual DbSet<AuthorizationCode> AuthorizationCodes { get; set; } = default!;

    public CoreIdentDbContext(DbContextOptions<CoreIdentDbContext> options) : base(options)
    { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // --- User Configuration ---
        modelBuilder.Entity<CoreIdentUser>(user =>
        {
            user.HasKey(u => u.Id);
            user.HasIndex(u => u.NormalizedUserName).IsUnique();
            user.Property(u => u.UserName).HasMaxLength(256);
            user.Property(u => u.NormalizedUserName).HasMaxLength(256);
            // PasswordHash can be long
            user.Property(u => u.ConcurrencyStamp).IsConcurrencyToken(); // Add ConcurrencyStamp to CoreIdentUser model if needed for EF

            // Relationship: User -> UserClaims (One-to-Many)
            user.HasMany(u => u.Claims).WithOne().HasForeignKey(uc => uc.UserId).IsRequired();

            // Ignored properties (computed)
            user.Ignore(u => u.IsLockedOut);

            user.ToTable("Users"); // Optional: Specify table name
        });

        modelBuilder.Entity<CoreIdentUserClaim>(userClaim =>
        {
            userClaim.HasKey(uc => uc.Id);
            userClaim.Property(uc => uc.ClaimType).HasMaxLength(256);
            // ClaimValue can be long

            userClaim.HasIndex(uc => uc.UserId); // Index for finding claims by user

            userClaim.ToTable("UserClaims");
        });

        // --- Refresh Token Configuration ---
        modelBuilder.Entity<CoreIdentRefreshToken>(refreshToken =>
        {
            // Use Handle as the key, but it should be stored hashed.
            // The actual token value presented by the client is not stored directly.
            refreshToken.HasKey(rt => rt.Handle);
            refreshToken.Property(rt => rt.Handle).HasMaxLength(128); // Adjust length as needed for hash
            
            // HashedHandle is the new preferred property for storing the hashed token value
            // In a future version, Handle will be phased out and HashedHandle will become the primary key
            refreshToken.Property(rt => rt.HashedHandle).HasMaxLength(128);
            refreshToken.HasIndex(rt => rt.HashedHandle); // Additional index for lookups

            refreshToken.HasIndex(rt => rt.SubjectId);
            refreshToken.HasIndex(rt => rt.ClientId);
            refreshToken.HasIndex(rt => rt.ExpirationTime); // Index for cleanup tasks
            refreshToken.HasIndex(rt => rt.FamilyId); // Index for token family operations

            refreshToken.Property(rt => rt.SubjectId).IsRequired().HasMaxLength(256);
            refreshToken.Property(rt => rt.ClientId).IsRequired().HasMaxLength(256);
            refreshToken.Property(rt => rt.FamilyId).IsRequired().HasMaxLength(128);

            refreshToken.ToTable("RefreshTokens");
        });

        // --- Client Configuration ---
        modelBuilder.Entity<CoreIdentClient>(client =>
        {
            client.HasKey(c => c.ClientId);
            client.Property(c => c.ClientId).HasMaxLength(256);
            client.Property(c => c.ClientName).HasMaxLength(256);

            // Relationship: Client -> ClientSecrets (One-to-Many)
            client.HasMany(c => c.ClientSecrets).WithOne(cs => cs.Client).HasForeignKey(cs => cs.ClientId).IsRequired().OnDelete(DeleteBehavior.Cascade);

            // Store collections as JSON strings (simple approach for collections of strings)
            // Requires EF Core 7+ for primitive collections. For older versions, use Value Converters.
            // EF Core 8+ has built-in support for JSON columns which is more robust.
            // Using Value Converter approach here for broader compatibility initially.

            var stringListConverter = new ValueConverter<List<string>, string>(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>()
            );
            var stringListComparer = new ValueComparer<List<string>>(
                (c1, c2) => c1!.SequenceEqual(c2!),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c.ToList()
            );

            client.Property(c => c.AllowedGrantTypes)
                  .HasConversion(stringListConverter)
                  .Metadata.SetValueComparer(stringListComparer);

            client.Property(c => c.RedirectUris)
                  .HasConversion(stringListConverter)
                  .Metadata.SetValueComparer(stringListComparer);

            client.Property(c => c.PostLogoutRedirectUris)
                  .HasConversion(stringListConverter)
                  .Metadata.SetValueComparer(stringListComparer);

            client.Property(c => c.AllowedScopes)
                  .HasConversion(stringListConverter)
                  .Metadata.SetValueComparer(stringListComparer);

            client.ToTable("Clients");
        });

        modelBuilder.Entity<CoreIdentClientSecret>(clientSecret =>
        {
            clientSecret.HasKey(cs => cs.Id);
            // Value should be hashed, can be long
            clientSecret.Property(cs => cs.Type).HasMaxLength(50);

            clientSecret.HasIndex(cs => cs.ClientId);

            clientSecret.ToTable("ClientSecrets");
        });

        // --- Scope Configuration ---
        modelBuilder.Entity<CoreIdentScope>(scope =>
        {
            scope.HasKey(s => s.Name);
            scope.Property(s => s.Name).HasMaxLength(256);
            scope.Property(s => s.DisplayName).HasMaxLength(256);

            // Relationship: Scope -> ScopeClaims (One-to-Many)
            scope.HasMany(s => s.UserClaims).WithOne(sc => sc.Scope).HasForeignKey(sc => sc.ScopeName).IsRequired().OnDelete(DeleteBehavior.Cascade);

            scope.ToTable("Scopes");
        });

        modelBuilder.Entity<CoreIdentScopeClaim>(scopeClaim =>
        {
            scopeClaim.HasKey(sc => sc.Id);
            scopeClaim.Property(sc => sc.Type).IsRequired().HasMaxLength(256);

            scopeClaim.HasIndex(sc => sc.ScopeName);

            scopeClaim.ToTable("ScopeClaims");
        });

        // --- Authorization Code Configuration ---
        modelBuilder.Entity<AuthorizationCode>(authCode =>
        {
            authCode.HasKey(ac => ac.CodeHandle);
            authCode.Property(ac => ac.CodeHandle).HasMaxLength(128); // Adjust length as needed for code handle representation

            authCode.Property(ac => ac.ClientId).IsRequired().HasMaxLength(256);
            authCode.Property(ac => ac.SubjectId).IsRequired().HasMaxLength(256);
            authCode.Property(ac => ac.RedirectUri).IsRequired(); // Redirect URIs can be long

            authCode.HasIndex(ac => ac.ExpirationTime); // Index for cleanup tasks

            // Configure RequestedScopes using the existing JSON converter and comparer
            var stringListConverterForAuthCode = new ValueConverter<List<string>, string>(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>()
            );
            var stringListComparerForAuthCode = new ValueComparer<List<string>>(
                (c1, c2) => c1!.SequenceEqual(c2!),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c.ToList()
            );

            authCode.Property(ac => ac.RequestedScopes)
                  .HasConversion(stringListConverterForAuthCode)
                  .Metadata.SetValueComparer(stringListComparerForAuthCode);

            authCode.ToTable("AuthorizationCodes");
        });
    }
} 