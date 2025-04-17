using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CoreIdent.Storage.EntityFrameworkCore.Migrations
{
    /// <inheritdoc />
    public partial class AddTokenFamilyFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "FamilyId",
                table: "RefreshTokens",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "PreviousTokenId",
                table: "RefreshTokens",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FamilyId",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "PreviousTokenId",
                table: "RefreshTokens");
        }
    }
}
