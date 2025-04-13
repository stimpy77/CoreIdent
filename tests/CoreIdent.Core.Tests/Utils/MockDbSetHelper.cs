using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Moq;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace CoreIdent.Core.Tests.Utils;

/// <summary>
/// Provides helper methods for creating mock DbSets for unit testing EF Core operations,
/// specifically handling async query providers.
/// </summary>
public static class MockDbSetHelper
{
    public static Mock<DbSet<T>> CreateMockDbSet<T>(List<T> sourceList) where T : class
    {
        var queryable = sourceList.AsQueryable();
        var mockSet = new Mock<DbSet<T>>();

        // Setup IQueryable properties using the custom async provider
        mockSet.As<IQueryable<T>>().Setup(m => m.Provider).Returns(new TestAsyncQueryProvider<T>(queryable.Provider));
        mockSet.As<IQueryable<T>>().Setup(m => m.Expression).Returns(queryable.Expression);
        mockSet.As<IQueryable<T>>().Setup(m => m.ElementType).Returns(queryable.ElementType);
        mockSet.As<IQueryable<T>>().Setup(m => m.GetEnumerator()).Returns(() => queryable.GetEnumerator());

        // Setup IAsyncEnumerable using a custom async enumerator
        mockSet.As<IAsyncEnumerable<T>>().Setup(m => m.GetAsyncEnumerator(It.IsAny<CancellationToken>()))
               .Returns(new TestAsyncEnumerator<T>(queryable.GetEnumerator()));

        // Setup common DbSet methods
        mockSet.Setup(m => m.Add(It.IsAny<T>())).Callback<T>(sourceList.Add);
        mockSet.Setup(m => m.AddRange(It.IsAny<IEnumerable<T>>())).Callback<IEnumerable<T>>(sourceList.AddRange);
        mockSet.Setup(m => m.Remove(It.IsAny<T>())).Callback<T>(t => sourceList.Remove(t));
        mockSet.Setup(m => m.RemoveRange(It.IsAny<IEnumerable<T>>())).Callback<IEnumerable<T>>(ts => { foreach (var t in ts.ToList()) { sourceList.Remove(t); } }); // ToList prevents modification during enumeration

        // --- FindAsync Mocking ---
        // Mock FindAsync based on primary key discovery (simple version)
        // Assumes single primary key named 'Id' or '{TypeName}Id'. Adapt if needed.
        // For composite keys or different naming, this needs adjustment.
        var primaryKeyProperty = typeof(T).GetProperty("Id") ?? typeof(T).GetProperty($"{typeof(T).Name}Id");
        if (primaryKeyProperty != null)
        {
            mockSet.Setup(m => m.FindAsync(It.IsAny<object[]>()))
                   .Returns<object[]>(async keyValues =>
                   {
                       if (keyValues == null || keyValues.Length == 0) return null;
                       var keyValue = keyValues[0];
                       await Task.Yield(); // Simulate async
                       return sourceList.FirstOrDefault(entity =>
                       {
                           var entityValue = primaryKeyProperty.GetValue(entity);
                           return entityValue != null && entityValue.Equals(keyValue);
                       });
                   });

            mockSet.Setup(m => m.FindAsync(It.IsAny<object[]>(), It.IsAny<CancellationToken>()))
                   .Returns<object[], CancellationToken>(async (keyValues, token) =>
                   {
                        if (keyValues == null || keyValues.Length == 0) return null;
                       var keyValue = keyValues[0];
                       await Task.Yield(); // Simulate async
                       token.ThrowIfCancellationRequested();
                       return sourceList.FirstOrDefault(entity =>
                       {
                           var entityValue = primaryKeyProperty.GetValue(entity);
                           return entityValue != null && entityValue.Equals(keyValue);
                       });
                   });
        }
        // For non-standard keys, FindAsync might need specific setup in the test itself.

        return mockSet;
    }

    // Helper for async enumeration mocking
    private class TestAsyncEnumerator<T> : IAsyncEnumerator<T>
    {
        private readonly IEnumerator<T> _enumerator;
        public TestAsyncEnumerator(IEnumerator<T> enumerator) => _enumerator = enumerator;
        public T Current => _enumerator.Current;
        public ValueTask DisposeAsync() => new(Task.Run(() => _enumerator.Dispose()));
        public ValueTask<bool> MoveNextAsync() => new(_enumerator.MoveNext());
    }

    // Helper Query Provider for async operations
    private class TestAsyncQueryProvider<TEntity> : IAsyncQueryProvider
    {
        private readonly IQueryProvider _inner;

        internal TestAsyncQueryProvider(IQueryProvider inner)
        {
            _inner = inner;
        }

        public IQueryable CreateQuery(Expression expression)
        {
            return new TestAsyncEnumerable<TEntity>(expression);
        }

        public IQueryable<TElement> CreateQuery<TElement>(Expression expression)
        {
            return new TestAsyncEnumerable<TElement>(expression);
        }

        public object? Execute(Expression expression)
        {
            return _inner.Execute(expression);
        }

        public TResult Execute<TResult>(Expression expression)
        {
            return _inner.Execute<TResult>(expression);
        }

        public TResult ExecuteAsync<TResult>(Expression expression, CancellationToken cancellationToken = default)
        {
            // Check cancellation token early
            cancellationToken.ThrowIfCancellationRequested();

            // Determine the kind of async operation being performed
            var resultType = typeof(TResult);
            bool isTask = typeof(Task).IsAssignableFrom(resultType);
            // If TResult is Task<T>, expectedResultType is T. Otherwise, it's TResult itself.
            var expectedResultType = isTask && resultType.IsGenericType ? resultType.GetGenericArguments()[0] : resultType;

            // Execute the expression synchronously using the inner LINQ provider
            object? executionResult;
            try
            {
                executionResult = _inner.Execute(expression);
            }
            catch (Exception ex)
            {
                // If sync execution fails, wrap the exception in a faulted Task
                return (TResult)(object)Task.FromException(ex);
            }

            // Wrap the synchronous result in the appropriate Task<T> type
            // Case 1: TResult is Task<List<TEntity>> (e.g., ToListAsync)
            if (isTask && expectedResultType.IsGenericType && expectedResultType.GetGenericTypeDefinition() == typeof(List<>))
            {
                var entityType = expectedResultType.GetGenericArguments()[0];
                // The synchronous LINQ provider executing the expression for ToListAsync
                // should return the underlying IEnumerable<TEntity>.
                if (executionResult is System.Collections.IEnumerable enumerableResult)
                {
                    try
                    {
                        // Cast the IEnumerable to IEnumerable<TEntity>
                        var castMethod = typeof(Enumerable).GetMethod(nameof(Enumerable.Cast))?.MakeGenericMethod(entityType);
                        var castedEnumerable = castMethod?.Invoke(null, new object[] { enumerableResult });

                        // Convert the IEnumerable<TEntity> to List<TEntity>
                        var toListMethod = typeof(Enumerable).GetMethod(nameof(Enumerable.ToList))?.MakeGenericMethod(entityType);
                        var typedListResult = toListMethod?.Invoke(null, new object[] { castedEnumerable! });

                        if (typedListResult != null)
                        {
                            // Wrap the List<TEntity> in Task.FromResult
                            var fromResultMethod = typeof(Task).GetMethod(nameof(Task.FromResult))?.MakeGenericMethod(expectedResultType);
                            return (TResult)fromResultMethod!.Invoke(null, new[] { typedListResult })!;
                        }
                    }
                    catch (Exception ex)
                    {
                        // If casting or ToList fails, return a faulted task
                        return (TResult)(object)Task.FromException(ex);
                    }
                }

                // If executionResult is null or not IEnumerable, return Task<List<TEntity>> with an empty list.
                var emptyList = Activator.CreateInstance(expectedResultType);
                var emptyFromResultMethod = typeof(Task).GetMethod(nameof(Task.FromResult))?.MakeGenericMethod(expectedResultType);
                 return (TResult)emptyFromResultMethod!.Invoke(null, new[] { emptyList })!;
            }

            // Case 2: TResult is Task<TEntity> (e.g., FirstOrDefaultAsync, SingleOrDefaultAsync)
            // Check if expectedResultType is the same as or assignable from executionResult's type
             if (isTask && !expectedResultType.IsArray && !expectedResultType.IsGenericType && (executionResult == null || expectedResultType.IsAssignableFrom(executionResult.GetType())))
            {
                 // Use reflection to call Task.FromResult<TEntity>(executionResult)
                 var fromResultMethod = typeof(Task).GetMethod(nameof(Task.FromResult))
                                                     ?.MakeGenericMethod(expectedResultType);
                 return (TResult)fromResultMethod!.Invoke(null, new[] { executionResult })!;
            }

            // Case 3: TResult is Task<int> (e.g., CountAsync)
            if (isTask && expectedResultType == typeof(int))
            {
                return (TResult)(object)Task.FromResult((int)(executionResult ?? 0));
            }

             // Case 4: TResult is Task<bool> (e.g., AnyAsync)
            if (isTask && expectedResultType == typeof(bool))
            {
                 return (TResult)(object)Task.FromResult((bool)(executionResult ?? false));
            }

            // --- Add handling for other common async methods as needed --- 
            // E.g., SumAsync, AverageAsync, etc.

            // Fallback or if no specific case matched
            // Try a simple Task.FromResult if TResult is Task<T>
             if (isTask && expectedResultType != null) {
                try
                {
                    var fromResultMethod = typeof(Task).GetMethod(nameof(Task.FromResult))
                                                        ?.MakeGenericMethod(expectedResultType);
                    if (fromResultMethod != null)
                    {
                         // Ensure the executionResult is assignable to the expected type
                        if (executionResult == null || expectedResultType.IsAssignableFrom(executionResult.GetType()))
                        {
                            return (TResult)fromResultMethod.Invoke(null, new[] { executionResult })!;
                        } else if (executionResult is IQueryable queryableResult) {
                             // Special handling if Execute returns IQueryable (e.g., for Includes)
                            var castMethod = typeof(Enumerable).GetMethod(nameof(Enumerable.Cast))
                                                               ?.MakeGenericMethod(expectedResultType);
                            var castedEnumerable = castMethod?.Invoke(null, new object[] { queryableResult });
                            return (TResult)fromResultMethod.Invoke(null, new[] { castedEnumerable })!;
                        }
                    }
                }
                catch (Exception ex) {
                     // If Task.FromResult fails, return a faulted task
                    return (TResult)(object)Task.FromException(ex);
                }
            }

            // If TResult is not Task<T> or no case matched, throw
            throw new NotSupportedException($"Async execution for result type {typeof(TResult)} with expression '{expression}' is not supported by this test provider. Synchronous result was: {executionResult?.GetType().Name ?? "null"}");
        }
    }

    // Helper Enumerable for async operations
    private class TestAsyncEnumerable<T> : EnumerableQuery<T>, IAsyncEnumerable<T>, IQueryable<T>
    {
        public TestAsyncEnumerable(IEnumerable<T> enumerable) : base(enumerable) { }
        public TestAsyncEnumerable(Expression expression) : base(expression) { }

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested(); // Check cancellation
            return new TestAsyncEnumerator<T>(this.AsEnumerable().GetEnumerator());
        }

        IQueryProvider IQueryable.Provider => new TestAsyncQueryProvider<T>(this);
    }
} 