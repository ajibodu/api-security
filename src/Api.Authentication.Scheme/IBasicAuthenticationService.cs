using Api.Authentication.Scheme.Models;

namespace Api.Authentication.Scheme;

public interface IBasicAuthenticationService
{
    public Task<AuthResponse> Authenticate(string username, string password);
}