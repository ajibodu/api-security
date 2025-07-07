using Api.Authentication.Jwt;

namespace SampleApiWithJwt;

public class CurrentUserProperties(CurrentUser currentUser)
{
    public string StaffId => currentUser.GetRequiredClaimValue(UserClaim.StaffId);
    public string FullName => currentUser.GetRequiredClaimValue(UserClaim.AuthChannel);

    public IEnumerable<string> Roles => currentUser.GetClaimValues(UserClaim.Role);
}