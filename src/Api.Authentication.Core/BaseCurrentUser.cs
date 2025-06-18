using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Api.Authentication.Core;

public abstract class BaseCurrentUser
{
    private readonly IEnumerable<Claim> _claims = null!;

    protected BaseCurrentUser(IHttpContextAccessor context)
    {
        if (context?.HttpContext == null)
            return;
        _claims = context.HttpContext.User.Claims;
    }
    
    public string? GetClaimValue(string claimType)
    {
        return _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
    
    public IEnumerable<string> GetClaimValues(string claimType)
    {
        return _claims.Where(c => c.Type == claimType).Select(c => c.Value);
    }
    
    public string GetRequiredClaimValue(string claimType)
    {
        return _claims.First(c => c.Type == claimType).Value;
    }

    public T? GetClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        return value != null ? converter(value) : default;
    }
    
    public IEnumerable<T> GetClaimsValue<T>(string claimType, Func<IEnumerable<string>, IEnumerable<T>> converter)
    {
        var value = _claims.Where(c => c.Type == claimType).Select(c => c.Value);
        return converter(value);
    }
    
    public T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.First(c => c.Type == claimType).Value;
        return converter(value);
    }
}