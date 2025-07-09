using Api.Security.Authentication.Jwt;

namespace SampleApiWithJwt;

public class CurrentUserProperties(ICurrentUser currentUser)
{
    public string StaffId => currentUser.GetRequiredClaimValue(UserClaim.StaffId);
    public string FullName => currentUser.GetRequiredClaimValue(UserClaim.AuthChannel);
    
    public IEnumerable<string> Roles => currentUser.GetClaimValues(UserClaim.Role);
    public DateTimeOffset IssuedDateTime => currentUser.IssuedDateTime;
}