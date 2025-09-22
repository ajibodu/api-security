using Api.Security.Authentication.Core;
using Api.Security.Authentication.Jwt.Models;

namespace Api.Security.Authentication.Jwt;

public interface ICurrentUser : IClaimResolver
{
    public DateTimeOffset IssuedDateTime { get; }
    public DateTimeOffset ExpirationDateTime { get; }
    public Task<TokenResponse> GenerateJwt(IList<CustomClaim> jwtClaims);
    public bool VerifyJwtAsync(string jwtToken);
    IList<CustomClaim> GetJwtClaimsAsync(string jwtToken);
    Task RevokeJwtAsync();
    bool EqualStandardClaimsEqual(string token1, string token2);
}