using System.Security.Claims;
using System.Text.Encodings.Web;
using Api.Authentication.Scheme.Configurations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Api.Authentication.Scheme.Handlers;

public class KeyAuthenticationHandler(
    IOptionsMonitor<KeyConfiguration> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IKeyAuthenticationService authenticationService)
    : AuthenticationHandler<KeyConfiguration>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.HeaderName, out var headerValue))
            return AuthenticateResult.Fail("Missing API Key");

        var authResult = await authenticationService.Authenticate(headerValue);
        if (!authResult.IsValid)
            return AuthenticateResult.Fail("Invalid API Key");
        
        Claim[] claims;
        if (authResult.Claims == null)
        {
            claims =
            [
                new Claim(ClaimTypes.Name, "AuthenticatedUser"),
                new Claim(Options.HeaderName, headerValue)
            ];
        }else
        {
            claims = authResult.Claims.Select(c => new Claim(c.Key, c.Value)).ToArray();
        }
        
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}