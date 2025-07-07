using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Api.Authentication.Scheme.Handlers;

public class BasicAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IBasicAuthenticationService authenticationService) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var headerValue) || string.IsNullOrEmpty(headerValue))
            return AuthenticateResult.Fail("Missing Authorization Header");

        try
        {
            var authHeader = AuthenticationHeaderValue.Parse(headerValue.ToString());
            if(authHeader.Parameter == null)
                return await Task.FromResult(AuthenticateResult.Fail("Basic Authorization is required"));
            
            var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
            var username = credentials[0];
            var password = credentials[1];

            var authResult = await authenticationService.Authenticate(username, password);
            if (!authResult.IsValid)
                return AuthenticateResult.Fail("Invalid Username or Password");

            Claim[] claims;
            if (authResult.Claims == null)
            {
                claims =
                [
                    new Claim(ClaimTypes.NameIdentifier, username),
                    new Claim(ClaimTypes.Name, username)
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
        catch
        {
            return AuthenticateResult.Fail("Invalid Authorization Header");
        }
    }
}