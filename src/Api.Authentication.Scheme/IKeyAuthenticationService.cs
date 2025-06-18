namespace Api.Authentication.Scheme;

public interface IKeyAuthenticationService
{
    Task<bool> Authenticate(string key);
}