using Api.Authentication.Scheme.Models;

namespace Api.Authentication.Scheme;

public class DelegateBasicAuthenticationService(Func<string, string, Task<AuthResponse>> authenticateFunc) : IBasicAuthenticationService
{
    public Task<AuthResponse> Authenticate(string username, string password)
    {
        return authenticateFunc(username, password);
    }
}

public class DelegateKeyAuthenticationService(Func<string, Task<AuthResponse>> authenticateFunc) : IKeyAuthenticationService
{
    public Task<AuthResponse> Authenticate(string key)
    {
        return authenticateFunc(key);
    }
}