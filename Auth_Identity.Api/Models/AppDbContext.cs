using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Runtime.CompilerServices;

namespace Auth_Identity.Api.Models;

public class AppDbContext : IdentityDbContext<IdentityUser>  
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
        
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        SeedRoles(builder);
    }

    private static void SeedRoles(ModelBuilder builder)
    {
        builder.Entity<IdentityRole>().HasData(
            new IdentityRole { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin"},
            new IdentityRole { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User"},
            new IdentityRole { Name = "HR", ConcurrencyStamp = "3", NormalizedName = "HR"}
            );
    }
}
