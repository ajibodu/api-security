namespace Api.Security.Authentication.Jwt;

sealed class ClaimComparer : IEqualityComparer<System.Security.Claims.Claim>
{
    public static readonly ClaimComparer Instance = new();

    public bool Equals(System.Security.Claims.Claim? x, System.Security.Claims.Claim? y) =>
        x?.Type == y?.Type && x?.Value == y?.Value;

    public int GetHashCode(System.Security.Claims.Claim obj) =>
        HashCode.Combine(obj.Type, obj.Value);
}