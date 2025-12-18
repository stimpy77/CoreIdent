using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core <see cref="DbContext"/> for CoreIdent storage.
/// </summary>
public class CoreIdentDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CoreIdentDbContext"/> class.
    /// </summary>
    /// <param name="options">The database context options.</param>
    public CoreIdentDbContext(DbContextOptions<CoreIdentDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Gets the set of revoked token records.
    /// </summary>
    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();
    /// <summary>
    /// Gets the set of OAuth/OIDC client records.
    /// </summary>
    public DbSet<ClientEntity> Clients => Set<ClientEntity>();
    /// <summary>
    /// Gets the set of scope records.
    /// </summary>
    public DbSet<ScopeEntity> Scopes => Set<ScopeEntity>();
    /// <summary>
    /// Gets the set of refresh token records.
    /// </summary>
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    /// <summary>
    /// Gets the set of authorization code records.
    /// </summary>
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes => Set<AuthorizationCodeEntity>();
    /// <summary>
    /// Gets the set of passwordless token records.
    /// </summary>
    public DbSet<PasswordlessTokenEntity> PasswordlessTokens => Set<PasswordlessTokenEntity>();
    /// <summary>
    /// Gets the set of user grant records.
    /// </summary>
    public DbSet<UserGrantEntity> UserGrants => Set<UserGrantEntity>();
    /// <summary>
    /// Gets the set of user records.
    /// </summary>
    public DbSet<UserEntity> Users => Set<UserEntity>();
    /// <summary>
    /// Gets the set of passkey credential records.
    /// </summary>
    public DbSet<PasskeyCredentialEntity> PasskeyCredentials => Set<PasskeyCredentialEntity>();

    /// <summary>
    /// Configures the EF Core model.
    /// </summary>
    /// <param name="modelBuilder">The model builder.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<RevokedToken>(entity =>
        {
            entity.HasKey(x => x.Jti);

            entity.Property(x => x.Jti)
                .IsRequired();

            entity.Property(x => x.TokenType)
                .IsRequired();

            entity.HasIndex(x => x.ExpiresAtUtc);
        });

        modelBuilder.Entity<ClientEntity>(entity =>
        {
            entity.HasKey(x => x.ClientId);

            entity.Property(x => x.ClientId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.ClientName)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.ClientType)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(x => x.ClientSecretHash)
                .HasMaxLength(500);

            entity.HasIndex(x => x.Enabled);
        });

        modelBuilder.Entity<ScopeEntity>(entity =>
        {
            entity.HasKey(x => x.Name);

            entity.Property(x => x.Name)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.DisplayName)
                .HasMaxLength(200);

            entity.Property(x => x.Description)
                .HasMaxLength(1000);

            entity.Property(x => x.UserClaimsJson)
                .IsRequired();

            entity.HasIndex(x => x.ShowInDiscoveryDocument);
        });

        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.HasKey(x => x.Handle);

            entity.Property(x => x.Handle)
                .IsRequired()
                .HasMaxLength(500);

            entity.Property(x => x.SubjectId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.ClientId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.FamilyId)
                .HasMaxLength(200);

            entity.Property(x => x.ScopesJson)
                .IsRequired();

            entity.HasIndex(x => x.SubjectId);
            entity.HasIndex(x => x.ClientId);
            entity.HasIndex(x => x.FamilyId);
            entity.HasIndex(x => x.ExpiresAt);
        });

        modelBuilder.Entity<UserGrantEntity>(entity =>
        {
            entity.HasKey(x => new { x.SubjectId, x.ClientId });

            entity.Property(x => x.SubjectId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.ClientId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.ScopesJson)
                .IsRequired();

            entity.HasIndex(x => x.ClientId);
            entity.HasIndex(x => x.SubjectId);
            entity.HasIndex(x => x.ExpiresAt);
        });

        modelBuilder.Entity<PasswordlessTokenEntity>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.Id)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.Email)
                .IsRequired()
                .HasMaxLength(256);

            entity.Property(x => x.TokenType)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(x => x.TokenHash)
                .IsRequired()
                .HasMaxLength(128);

            entity.HasIndex(x => x.TokenHash)
                .IsUnique();

            entity.HasIndex(x => x.Email);
            entity.HasIndex(x => new { x.TokenType, x.Email });
            entity.HasIndex(x => x.ExpiresAt);
            entity.HasIndex(x => x.ConsumedAt);
        });

        modelBuilder.Entity<AuthorizationCodeEntity>(entity =>
        {
            entity.HasKey(x => x.Handle);

            entity.Property(x => x.Handle)
                .IsRequired()
                .HasMaxLength(500);

            entity.Property(x => x.ClientId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.SubjectId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.RedirectUri)
                .IsRequired();

            entity.Property(x => x.ScopesJson)
                .IsRequired();

            entity.Property(x => x.CodeChallenge)
                .IsRequired();

            entity.Property(x => x.CodeChallengeMethod)
                .IsRequired();

            entity.HasIndex(x => x.ClientId);
            entity.HasIndex(x => x.SubjectId);
            entity.HasIndex(x => x.ExpiresAt);
        });

        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.Id)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.UserName)
                .IsRequired()
                .HasMaxLength(256);

            entity.Property(x => x.NormalizedUserName)
                .IsRequired()
                .HasMaxLength(256);

            entity.Property(x => x.PasswordHash)
                .HasMaxLength(500);

            entity.Property(x => x.ClaimsJson)
                .IsRequired();

            entity.HasIndex(x => x.NormalizedUserName)
                .IsUnique();
        });

        modelBuilder.Entity<PasskeyCredentialEntity>(entity =>
        {
            entity.HasKey(x => x.CredentialId);

            entity.Property(x => x.UserId)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.CredentialId)
                .IsRequired();

            entity.Property(x => x.PublicKey)
                .IsRequired();

            entity.Property(x => x.CreatedAt)
                .IsRequired();

            entity.Property(x => x.TransportsJson)
                .HasMaxLength(2000);

            entity.Property(x => x.Name)
                .HasMaxLength(200);

            entity.HasIndex(x => x.UserId);
        });
    }
}
