using Api.Authentication.Core;
using Api.Authentication.Jwt.Models;

namespace Api.Authentication.Jwt;

public interface ICurrentUser : IClaimResolver
{
    public DateTimeOffset IssuedDateTime { get; }
    public DateTimeOffset ExpirationDateTime { get; }
    public Task<TokenResponse> GenerateJwt(IList<CustomClaim> jwtClaims);
    public bool VerifyJwtAsync(string jwtToken);
    IList<CustomClaim> GetJwtClaimsAsync(string jwtToken);
    Task RevokeJwtAsync();
}