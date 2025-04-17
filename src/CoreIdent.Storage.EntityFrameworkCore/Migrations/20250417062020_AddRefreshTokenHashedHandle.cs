using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CoreIdent.Storage.EntityFrameworkCore.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenHashedHandle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "HashedHandle",
                table: "RefreshTokens",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_HashedHandle",
                table: "RefreshTokens",
                column: "HashedHandle");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_HashedHandle",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "HashedHandle",
                table: "RefreshTokens");
        }
    }
}
