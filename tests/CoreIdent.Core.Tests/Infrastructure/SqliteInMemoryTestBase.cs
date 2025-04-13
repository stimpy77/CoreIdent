using CoreIdent.Storage.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System;

namespace CoreIdent.Core.Tests.Infrastructure;

/// <summary>
/// Base class for tests that require an in-memory SQLite database using CoreIdentDbContext.
/// Manages the connection and context lifecycle, ensuring the database schema is created.
/// </summary>
public abstract class SqliteInMemoryTestBase : IDisposable
{
    private readonly SqliteConnection _connection;
    protected readonly CoreIdentDbContext DbContext;

    protected SqliteInMemoryTestBase()
    {
        // Connection string for SQLite in-memory database. "DataSource=:memory:" creates a temporary, private database.
        // "Cache=Shared" is often used to allow multiple connections to the same in-memory db, but requires careful connection management.
        // For simplicity here, we'll use a single connection per test class instance.
        var connectionString = "DataSource=:memory:";
        _connection = new SqliteConnection(connectionString);

        // The connection MUST be opened before passing it to the context
        _connection.Open();

        var options = new DbContextOptionsBuilder<CoreIdentDbContext>()
            .UseSqlite(_connection)
            .Options;

        DbContext = new CoreIdentDbContext(options);

        // Ensure the database schema is created based on the DbContext model
        DbContext.Database.EnsureCreated();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Ensure the database is deleted (optional for in-memory, but good practice)
            // DbContext.Database.EnsureDeleted(); // Might not be needed as connection close destroys it

            DbContext.Dispose();

            // Close and dispose the connection to release the in-memory database
            _connection.Close();
            _connection.Dispose();
        }
    }
} 