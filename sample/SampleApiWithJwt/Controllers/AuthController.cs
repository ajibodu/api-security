using Microsoft.AspNetCore.Mvc;
using Api.Authentication.Jwt;
using Api.Authentication.Jwt.Models;

namespace SampleApiWithJwt.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// Authenticates a user and returns a JWT token.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="password">The password.</param>
    /// <returns>JWT token and expiration.</returns>
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(string username, string password)
    {
        // For demonstration, accept any username/password. Replace with real validation.
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return BadRequest("Username and password are required.");

        var claims = new List<CustomClaim>
        {
            new("sub", username, IsUniqueId: true),
            new("role", "User")
        };
        var token = await currentUser.GenerateJwt(claims);
        return Ok(token);
    }
}
