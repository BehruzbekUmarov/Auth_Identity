using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Auth_Identity.Api.Migrations
{
    /// <inheritdoc />
    public partial class SeededRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1895fd69-fe2c-456e-8614-d2f1462154a0", "2", "User", "User" },
                    { "cd99c4f8-09cf-4d29-964a-5493db4d7cbb", "3", "HR", "HR" },
                    { "dfd3ce97-a8a0-488a-af63-0e6596d5d862", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1895fd69-fe2c-456e-8614-d2f1462154a0");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "cd99c4f8-09cf-4d29-964a-5493db4d7cbb");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "dfd3ce97-a8a0-488a-af63-0e6596d5d862");
        }
    }
}
