namespace Api.Security.Authentication.Core;

public interface IClaimResolver
{
    string? GetClaimValue(string claimType);
    IEnumerable<string> GetClaimValues(string claimType);
    string GetRequiredClaimValue(string claimType);
    T? GetClaimValue<T>(string claimType, Func<string, T> converter);
    IEnumerable<T> GetClaimsValue<T>(string claimType, Func<IEnumerable<string>, IEnumerable<T>> converter);
    T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter);
}