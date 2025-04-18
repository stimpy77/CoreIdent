using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CoreIdent.Storage.EntityFrameworkCore.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthorizationCodeStore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    CodeHandle = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    SubjectId = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    RedirectUri = table.Column<string>(type: "TEXT", nullable: false),
                    RequestedScopes = table.Column<string>(type: "TEXT", nullable: false),
                    Nonce = table.Column<string>(type: "TEXT", nullable: true),
                    CodeChallenge = table.Column<string>(type: "TEXT", nullable: true),
                    CodeChallengeMethod = table.Column<string>(type: "TEXT", nullable: true),
                    CreationTime = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpirationTime = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.CodeHandle);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_ExpirationTime",
                table: "AuthorizationCodes",
                column: "ExpirationTime");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthorizationCodes");
        }
    }
}
