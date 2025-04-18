﻿// <auto-generated />
using System;
using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace CoreIdent.Storage.EntityFrameworkCore.Migrations
{
    [DbContext(typeof(CoreIdentDbContext))]
    partial class CoreIdentDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "9.0.4");

            modelBuilder.Entity("CoreIdent.Core.Models.AuthorizationCode", b =>
                {
                    b.Property<string>("CodeHandle")
                        .HasMaxLength(128)
                        .HasColumnType("TEXT");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<string>("CodeChallenge")
                        .HasColumnType("TEXT");

                    b.Property<string>("CodeChallengeMethod")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreationTime")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ExpirationTime")
                        .HasColumnType("TEXT");

                    b.Property<string>("Nonce")
                        .HasColumnType("TEXT");

                    b.Property<string>("RedirectUri")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RequestedScopes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("SubjectId")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.HasKey("CodeHandle");

                    b.HasIndex("ExpirationTime");

                    b.ToTable("AuthorizationCodes", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentClient", b =>
                {
                    b.Property<string>("ClientId")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<int>("AbsoluteRefreshTokenLifetime")
                        .HasColumnType("INTEGER");

                    b.Property<int>("AccessTokenLifetime")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("AllowOfflineAccess")
                        .HasColumnType("INTEGER");

                    b.Property<string>("AllowedGrantTypes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("AllowedScopes")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("AuthorizationCodeLifetime")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ClientName")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<string>("ClientUri")
                        .HasColumnType("TEXT");

                    b.Property<bool>("Enabled")
                        .HasColumnType("INTEGER");

                    b.Property<int>("IdentityTokenLifetime")
                        .HasColumnType("INTEGER");

                    b.Property<string>("LogoUri")
                        .HasColumnType("TEXT");

                    b.Property<string>("PostLogoutRedirectUris")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("RedirectUris")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("RefreshTokenExpiration")
                        .HasColumnType("INTEGER");

                    b.Property<int>("RefreshTokenUsage")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("RequireConsent")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("RequirePkce")
                        .HasColumnType("INTEGER");

                    b.Property<int>("SlidingRefreshTokenLifetime")
                        .HasColumnType("INTEGER");

                    b.HasKey("ClientId");

                    b.ToTable("Clients", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentClientSecret", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("Created")
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("TEXT");

                    b.Property<string>("Type")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("TEXT");

                    b.Property<string>("Value")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ClientId");

                    b.ToTable("ClientSecrets", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentRefreshToken", b =>
                {
                    b.Property<string>("Handle")
                        .HasMaxLength(128)
                        .HasColumnType("TEXT");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<DateTime?>("ConsumedTime")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("CreationTime")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("ExpirationTime")
                        .HasColumnType("TEXT");

                    b.Property<string>("FamilyId")
                        .IsRequired()
                        .HasMaxLength(128)
                        .HasColumnType("TEXT");

                    b.Property<string>("HashedHandle")
                        .HasMaxLength(128)
                        .HasColumnType("TEXT");

                    b.Property<string>("PreviousTokenId")
                        .HasColumnType("TEXT");

                    b.Property<string>("SubjectId")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.HasKey("Handle");

                    b.HasIndex("ClientId");

                    b.HasIndex("ExpirationTime");

                    b.HasIndex("FamilyId");

                    b.HasIndex("HashedHandle");

                    b.HasIndex("SubjectId");

                    b.ToTable("RefreshTokens", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentScope", b =>
                {
                    b.Property<string>("Name")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<string>("Description")
                        .HasColumnType("TEXT");

                    b.Property<string>("DisplayName")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<bool>("Emphasize")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("Enabled")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("Required")
                        .HasColumnType("INTEGER");

                    b.HasKey("Name");

                    b.ToTable("Scopes", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentScopeClaim", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("ScopeName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Type")
                        .IsRequired()
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("ScopeName");

                    b.ToTable("ScopeClaims", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentUser", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("TEXT");

                    b.Property<int>("AccessFailedCount")
                        .HasColumnType("INTEGER");

                    b.Property<string>("ConcurrencyStamp")
                        .IsConcurrencyToken()
                        .HasColumnType("TEXT");

                    b.Property<bool>("LockoutEnabled")
                        .HasColumnType("INTEGER");

                    b.Property<DateTimeOffset?>("LockoutEnd")
                        .HasColumnType("TEXT");

                    b.Property<string>("NormalizedUserName")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<string>("PasswordHash")
                        .HasColumnType("TEXT");

                    b.Property<string>("UserName")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("NormalizedUserName")
                        .IsUnique();

                    b.ToTable("Users", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentUserClaim", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("ClaimType")
                        .HasMaxLength(256)
                        .HasColumnType("TEXT");

                    b.Property<string>("ClaimValue")
                        .HasColumnType("TEXT");

                    b.Property<string>("UserId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("UserClaims", (string)null);
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentClientSecret", b =>
                {
                    b.HasOne("CoreIdent.Core.Models.CoreIdentClient", "Client")
                        .WithMany("ClientSecrets")
                        .HasForeignKey("ClientId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Client");
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentScopeClaim", b =>
                {
                    b.HasOne("CoreIdent.Core.Models.CoreIdentScope", "Scope")
                        .WithMany("UserClaims")
                        .HasForeignKey("ScopeName")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Scope");
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentUserClaim", b =>
                {
                    b.HasOne("CoreIdent.Core.Models.CoreIdentUser", null)
                        .WithMany("Claims")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentClient", b =>
                {
                    b.Navigation("ClientSecrets");
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentScope", b =>
                {
                    b.Navigation("UserClaims");
                });

            modelBuilder.Entity("CoreIdent.Core.Models.CoreIdentUser", b =>
                {
                    b.Navigation("Claims");
                });
#pragma warning restore 612, 618
        }
    }
}
