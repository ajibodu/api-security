namespace Api.Authentication.Scheme;

public interface IBasicAuthenticationService
{
    Task<bool> Authenticate(string username, string password);
}