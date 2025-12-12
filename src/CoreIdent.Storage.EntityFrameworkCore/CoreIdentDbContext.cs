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
    }
}
