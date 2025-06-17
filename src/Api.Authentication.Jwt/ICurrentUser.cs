using Api.Authentication.Jwt.Models;

namespace Api.Authentication.Jwt;

public interface ICurrentUser
{
    string? GetClaimValue(string claimType);
    string GetRequiredClaimValue(string claimType);
    T? GetClaimValue<T>(string claimType, Func<string, T> converter);
    T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter);
    public DateTimeOffset IssuedDateTime { get; }
    public DateTimeOffset ExpirationDateTime { get; }
    public Task<string> GenerateJwt(IList<CustomClaim> jwtClaims);
    public bool VerifyJwtAsync(string jwtToken);
    IList<CustomClaim> GetJwtClaimsAsync(string jwtToken);
    Task RevokeJwtAsync();
}