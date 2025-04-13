using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration; // Required for configuration building if needed
using System.IO; // Required for Path combining

namespace CoreIdent.Storage.EntityFrameworkCore.Factories;

/// <summary>
/// Factory for creating CoreIdentDbContext instances during design time (e.g., for migrations).
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<CoreIdentDbContext>
{
    public CoreIdentDbContext CreateDbContext(string[] args)
    {
        // TODO: Consider reading connection string from config/user secrets for more flexibility
        // For now, use a simple default SQLite connection string, similar to the README example.
        // It will create the DB file in the project root of where the command is executed from.
        var connectionString = "DataSource=coreident_design.db;Cache=Shared";

        var optionsBuilder = new DbContextOptionsBuilder<CoreIdentDbContext>();
        optionsBuilder.UseSqlite(connectionString
            // Optional: Specify migrations assembly if it differs from the DbContext project
            // , b => b.MigrationsAssembly("CoreIdent.Storage.EntityFrameworkCore") // Comma needed if uncommented
            );

        return new CoreIdentDbContext(optionsBuilder.Options);
    }

    // Optional: Helper method to build configuration if needed
    // private IConfigurationRoot BuildConfiguration()
    // {
    //     var builder = new ConfigurationBuilder()
    //         .SetBasePath(Directory.GetCurrentDirectory()) // Or specify the path to your web project
    //         .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    //         .AddUserSecrets<DesignTimeDbContextFactory>(optional: true) // If using user secrets
    //         .AddEnvironmentVariables();
    //     return builder.Build();
    // }
} 