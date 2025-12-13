using CoreIdent.Storage.EntityFrameworkCore.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdent.Storage.EntityFrameworkCore;

public class CoreIdentDbContext : DbContext
{
    public CoreIdentDbContext(DbContextOptions<CoreIdentDbContext> options)
        : base(options)
    {
    }

    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();
    public DbSet<ClientEntity> Clients => Set<ClientEntity>();
    public DbSet<ScopeEntity> Scopes => Set<ScopeEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes => Set<AuthorizationCodeEntity>();
    public DbSet<UserGrantEntity> UserGrants => Set<UserGrantEntity>();
    public DbSet<UserEntity> Users => Set<UserEntity>();

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
    }
}
