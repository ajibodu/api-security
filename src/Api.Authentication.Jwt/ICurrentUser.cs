using Api.Authentication.Jwt.Models;

namespace Api.Authentication.Jwt;

public interface ICurrentUser
{
    string? GetClaimValue(string claimType);
    IEnumerable<string> GetClaimValues(string claimType);
    string GetRequiredClaimValue(string claimType);
    T? GetClaimValue<T>(string claimType, Func<string, T> converter);
    IEnumerable<T> GetClaimsValue<T>(string claimType, Func<IEnumerable<string>, IEnumerable<T>> converter);
    T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter);
    public DateTimeOffset IssuedDateTime { get; }
    public DateTimeOffset ExpirationDateTime { get; }
    public Task<TokenResponse> GenerateJwt(IList<CustomClaim> jwtClaims);
    public bool VerifyJwtAsync(string jwtToken);
    IList<CustomClaim> GetJwtClaimsAsync(string jwtToken);
    Task RevokeJwtAsync();
}