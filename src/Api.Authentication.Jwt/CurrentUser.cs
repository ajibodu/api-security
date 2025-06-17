using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.Authentication.Core;
using Api.Authentication.Jwt.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Api.Authentication.Jwt;

public class CurrentUser : ICurrentUser
{
    private readonly ISessionManager _sessionManager = null!;
    private readonly Configuration _configuration = null!;
    private readonly IEnumerable<Claim> _claims = null!;

    public CurrentUser(IHttpContextAccessor context, IOptions<Configuration> configuration, ISessionManager? sessionManager = null)
    {
        if (context?.HttpContext == null)
            return;
        _claims = context.HttpContext.User.Claims;
        _configuration = configuration.Value;

        if (_configuration.Session != null)
            _sessionManager = sessionManager ?? throw new NullReferenceException($"Mission Implementation of {nameof(ISessionManager)}");
    }
    
    public string? GetClaimValue(string claimType)
    {
        return _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
    
    public string GetRequiredClaimValue(string claimType)
    {
        return _claims.First(c => c.Type == claimType).Value;
    }

    public T? GetClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        return value != null ? converter(value) : default;
    }
    
    public T GetRequiredClaimValue<T>(string claimType, Func<string, T> converter)
    {
        var value = _claims.First(c => c.Type == claimType).Value;
        return converter(value);
    }
    
    public DateTimeOffset IssuedDateTime => GetRequiredClaimValue(JwtRegisteredClaimNames.Iat, value => DateTimeOffset.FromUnixTimeSeconds(long.Parse(value)));

    public DateTimeOffset ExpirationDateTime => GetRequiredClaimValue(JwtRegisteredClaimNames.Exp, value => DateTimeOffset.FromUnixTimeSeconds(long.Parse(value)));

    public async Task<string> GenerateJwt(IList<CustomClaim> jwtClaims)
    {
        if (jwtClaims == null || !jwtClaims.Any())
            throw new ArgumentException("At least one claim is required", nameof(jwtClaims));
        if (string.IsNullOrWhiteSpace(_configuration.SecretKey))
            throw new InvalidOperationException("JWT SecretKey is not configured");

        var uniqueClaims = jwtClaims.Where(claim => claim.IsUniqueId).ToList();
        if (uniqueClaims.Count != 1)
            throw new InvalidOperationException("Exactly one unique claim is required for session management");
        var uniqueClaim = uniqueClaims.Single();
        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var versionClaim = jwtClaims.FirstOrDefault(c => c.Type == SystemClaim.JwtVersion);
        if (versionClaim != null)
            versionClaim.Value = (int.Parse(versionClaim.Value) + 1).ToString();
        else
            jwtClaims.Add(new CustomClaim(SystemClaim.JwtVersion, "1", CustomClaimValueTypes.Integer));
        
        jwtClaims = jwtClaims.Where(claim => !_defaultClaimTypesToExclude.Contains(claim.Type)).ToList();
        
        var securityClaims = jwtClaims
            .Select(claim => new Claim(claim.Type, claim.Value, claim.ValueType))
            .ToList();
        
        securityClaims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), CustomClaimValueTypes.Integer64));
        securityClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        securityClaims.Add(new Claim(JwtRegisteredClaimNames.Nbf, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), CustomClaimValueTypes.Integer64));
        securityClaims.Add(new Claim(JwtRegisteredClaimNames.Sub, uniqueClaim.Value));


        var token = new JwtSecurityToken(
            _configuration.Issuer,
            _configuration.Audience,
            securityClaims,
            expires: DateTime.UtcNow.AddMinutes(_configuration.ExpirationInMinutes),
            signingCredentials: credentials
        );

        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        if (_configuration.Session != null)
            await _sessionManager.SetAsync(uniqueClaim.Value, jwtToken, _configuration.Session.ActivityWindowMinutes);
        
        return jwtToken;
    }
    
    public bool VerifyJwtAsync(string jwtToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration.Issuer,
            ValidAudience = _configuration.Audience,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecretKey))
        };

        try
        {
            tokenHandler.ValidateToken(jwtToken, validationParameters, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    public IList<CustomClaim> GetJwtClaimsAsync(string jwtToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration.Issuer,
            ValidAudience = _configuration.Audience,
            ValidateLifetime = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecretKey))
        };

        try
        {
            var op = tokenHandler.ValidateToken(jwtToken, validationParameters, out _);
            return op.Claims.Select(c => new CustomClaim(c.Type, c.Value, c.ValueType)).ToList();
        }
        catch
        {
            return new List<CustomClaim>();
        }
    }

    public async Task RevokeJwtAsync()
    {
        if(_sessionManager == null)
            throw new InvalidOperationException($"Mission Implementation of {nameof(ISessionManager)}");
        
        await _sessionManager.RemoveAsync(GetRequiredClaimValue(JwtRegisteredClaimNames.Sub));
    }
    
    private readonly HashSet<string> _defaultClaimTypesToExclude =
    [
        JwtRegisteredClaimNames.Iat,
        JwtRegisteredClaimNames.Iss,
        JwtRegisteredClaimNames.Aud,
        JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf,
        JwtRegisteredClaimNames.Sub,
        JwtRegisteredClaimNames.Jti
    ];
}