using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Api.Security.Authentication.Core;

/// <summary>
/// Provides base functionality for accessing claims of the current user.
/// </summary>
public class ClaimResolver : IClaimResolver
{
    // Consider initializing _claims to an empty list to avoid null reference issues.
    private readonly IEnumerable<Claim> _claims = null!;

    /// <summary>
    /// Initializes a new instance of <see cref="ClaimResolver"/> using the provided HTTP context accessor.
    /// </summary>
    /// <param name="context">The HTTP context accessor.</param>
    public ClaimResolver(IHttpContextAccessor context)
    {
        if (context?.HttpContext == null)
            return;
        _claims = context.HttpContext.User.Claims;
    }
    
    /// <summary>
    /// Gets the value of the first claim matching the specified type, or null if not found.
    /// </summary>
    /// <param name="claimType">The claim type to search for.</param>
    /// <returns>The claim value, or null if not found.</returns>
    public string? GetClaimValue(string claimType)
    {
        return _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
    
    /// <summary>
    /// Gets all values for claims matching the specified type.
    /// </summary>
    /// <param name="claimType">The claim type to search for.</param>
    /// <returns>An enumerable of claim values.</returns>
    public IEnumerable<string> GetClaimValues(string claimType)
    {
        return _claims.Where(c => c.Type == claimType).Select(c => c.Value);
    }
    
    /// <summary>
    /// Gets the value of the first claim matching the specified type, or throws if not found.
    /// </summary>
    /// <param name="claimType">The claim type to search for.</param>
    /// <returns>The claim value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the claim is not found.</exception>
    public string GetRequiredClaimValue(string claimType)
    {
        return _claims.First(c => c.Type == claimType).Value;
    }

    /// <summary>
    /// Gets the value of the first claim matching the specified type and converts it to <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The target type.</typeparam>
    /// <param name="claimType">The claim type to search for.</param>
    /// <param name="converter">A function to convert the claim value.</param>
    /// <returns>The converted claim value, or default if not found.</returns>
    public T? GetClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        return value != null ? converter(value) : default;
    }
    
    /// <summary>
    /// Gets all values for claims matching the specified type and converts them to <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The target type.</typeparam>
    /// <param name="claimType">The claim type to search for.</param>
    /// <param name="converter">A function to convert the claim values.</param>
    /// <returns>An enumerable of converted claim values.</returns>
    public IEnumerable<T> GetClaimsValue<T>(string claimType, Func<IEnumerable<string>, IEnumerable<T>> converter)
    {
        var value = _claims.Where(c => c.Type == claimType).Select(c => c.Value);
        return converter(value);
    }
    
    /// <summary>
    /// Gets the value of the first claim matching the specified type, converts it to <typeparamref name="T"/>, or throws if not found.
    /// </summary>
    /// <typeparam name="T">The target type.</typeparam>
    /// <param name="claimType">The claim type to search for.</param>
    /// <param name="converter">A function to convert the claim value.</param>
    /// <returns>The converted claim value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the claim is not found.</exception>
    public T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.First(c => c.Type == claimType).Value;
        return converter(value);
    }
}