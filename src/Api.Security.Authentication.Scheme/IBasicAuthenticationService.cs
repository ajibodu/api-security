using Api.Security.Authentication.Scheme.Models;

namespace Api.Security.Authentication.Scheme;

public interface IBasicAuthenticationService
{
    public Task<AuthResponse> Authenticate(string username, string password);
}