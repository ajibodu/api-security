# API Security Library

A robust, flexible authentication solution for .NET applications that simplifies the implementation of secure API endpoints using industry-standard authentication schemes.

## 🌟 Features

- **Multiple Authentication Schemes**: Support for JWT, Basic, and API Key authentication
- **Flexible Configuration**: Configure via appsettings.json or programmatically
- **Customizable**: Easily extend with your own authentication logic
- **Developer-Friendly**: Simple, fluent API for quick implementation
- **Modern**: Built for .NET 8.0+ with full async support
- **Production-Ready**: Comprehensive security features with best practices built-in
- **Session Management**: Built-in JWT session tracking and revocation support
- **Claim Utilities**: Easy claim value resolution with CurrentUserProperties

## 📦 Installation

```shell
# Core authentication package
dotnet add package Api.Security.Authentication

# JWT authentication (if needed)
dotnet add package Api.Security.Authentication.Jwt

# Basic and Key-based authentication (if needed)
dotnet add package Api.Security.Authentication.Scheme
```

## 🚀 Quick Start

### Basic Setup in Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);

// Add API Authentication with JWT Bearer scheme
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(builder.Configuration.GetRequiredConfig<JwtConfiguration>(nameof(JwtConfiguration)));

// Register controllers and enable authorization
builder.Services.AddControllers();
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the app to use authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

## 📑 Table of Contents

- [Authentication Schemes](#-authentication-schemes)
   - [JWT Bearer Authentication](#jwt-bearer-authentication)
      - [JWT Session Management](#-jwt-session-management)
   - [Basic Authentication](#basic-authentication)
   - [API Key Authentication](#api-key-authentication)
- [Working with Claims](#-working-with-claims)
- [Multiple Authentication Schemes](#-multiple-authentication-schemes)
- [Security Best Practices](#-security-best-practices)
   - [JWT Security](#jwt-security)
   - [Basic Authentication Security](#basic-authentication)
   - [API Key Security](#api-key-security)
- [Additional Configuration](#-additional-configuration)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)
- [Contributing](#-contributing)

## 🔐 Authentication Schemes

### JWT Bearer Authentication

JSON Web Tokens provide a stateless, secure method for authentication that works well for APIs and SPAs.

#### Configuration in appsettings.json

```json
{
  "JwtConfiguration": {
    "SecretKey": "your-secure-secret-key-at-least-256-bits-long",
    "Issuer": "your-application-name",
    "Audience": "your-application-clients",
    "ExpirationInMinutes": 60,
    "Session": {
      "ActivityWindowMinutes": 30
    }
  }
}
```

#### Using Configuration from appsettings.json

```csharp
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(builder.Configuration.GetRequiredSection<JwtConfiguration>(nameof(JwtConfiguration)));
```

#### Programmatic Configuration

```csharp
builder.Services.AddApiAuthentication()
    .WithJwtBearer(options => {
        options.SecretKey = "your-secure-secret-key-at-least-256-bits-long";
        options.Issuer = "your-application-name";
        options.Audience = "your-application-clients";
        options.ExpirationInMinutes = 60;
        options.Session = new UserSessionConfiguration {
            ActivityWindowMinutes = 30
        };
    });
```

#### JWT Session Management

The library provides built-in session management capabilities for JWT tokens, allowing you to enforce activity windows and revoke tokens.

##### Configuring Session Management

Enabling session management is as simple as adding the `Session` configuration in your JWT settings:

```json
{
  "Jwt": {
    "Session": {
      "ActivityWindowMinutes": 30
    }
  }
}
```

With this configuration, user sessions will be automatically revoked if there is no activity within the specified `ActivityWindowMinutes` (30 minutes in this example).

##### Implementing ISessionManager

When session management is enabled, you must provide an implementation of `ISessionManager` to handle session storage and retrieval:

```csharp
public class DatabaseSessionManager : ISessionManager
{
    private readonly ISessionRepository _repository;

    public DatabaseSessionManager(ISessionRepository repository)
    {
        _repository = repository;
    }

    public async Task SetAsync(string identifier, string token, int activityWindowMinute)
    {
        await _repository.SaveSessionAsync(identifier, token, DateTime.UtcNow.AddMinutes(activityWindowMinute));
    }

    public async Task<bool> TryGetValue(string identifier, out string? token)
    {
        var session = await _repository.GetSessionAsync(identifier);
        token = session?.Token;
        return token != null;
    }

    public async Task UpdateActivityAsync(string identifier, int activityWindowMinute)
    {
        await _repository.UpdateLastActivityAsync(identifier, DateTime.UtcNow.AddMinutes(activityWindowMinute));
    }

    public async Task RemoveAsync(string identifier)
    {
        await _repository.RemoveSessionAsync(identifier);
    }
}
```

##### Managing Sessions

The library automatically handles session tracking and validation, but you can also manually revoke sessions:

```csharp
[Authorize]
[HttpPost("logout")]
public async Task<IActionResult> Logout([FromServices] ICurrentUser currentUser)
{
    await currentUser.RevokeJwtAsync();
    return Ok(new { message = "Logged out successfully" });
}
```

### Basic Authentication

Basic Authentication provides a simple username/password authentication mechanism suitable for internal tools or development environments.

#### Simple Static Credentials

```csharp
builder.Services
    .AddApiAuthentication()
    .WithBasicScheme(new BasicConfiguration("admin","secure-password"));
```

#### Custom Authentication Service

```csharp
// Implement your custom service
public class MyBasicAuthService : IBasicAuthenticationService
{
    private readonly IUserRepository _userRepository;

    public MyBasicAuthService(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<AuthResponse> Authenticate(string username, string password)
    {
        var user = await _userRepository.FindByUsernameAsync(username);
        if (user == null) return new AuthResponse(false);

        bool isValid = await _userRepository.ValidatePasswordAsync(user, password);
        return new AuthResponse(isValid);
    }
}

// Register in your startup
builder.Services
    .AddApiAuthentication()
    .WithBasicScheme<MyBasicAuthService>();
```

#### Using Inline Delegate

```csharp
builder.Services
    .AddApiAuthentication()
    .WithBasicScheme(async (username, password) => {
        // Your authentication logic here
        bool isValid = username == "admin" && password == "password123";
        return new AuthResponse(isValid);
    });
```

### API Key Authentication

API Key authentication provides a simple, token-based approach suitable for machine-to-machine communication.

#### Simple Key Configuration

```csharp
builder.Services
    .AddApiAuthentication()
    .WithKeyScheme(new SimpleKeyConfiguration("X-API-Key", "your-api-key-value"), "ApiKey");
```

#### Custom Key Authentication Service

```csharp
// Implement your custom service
public class MyApiKeyService : IKeyAuthenticationService
{
    private readonly IApiKeyRepository _apiKeyRepository;

    public MyApiKeyService(IApiKeyRepository apiKeyRepository)
    {
        _apiKeyRepository = apiKeyRepository;
    }

    public async Task<AuthResponse> Authenticate(string key)
    {
        var apiKey = await _apiKeyRepository.FindByKeyAsync(key);
        return new AuthResponse(apiKey != null && !apiKey.IsRevoked);
    }
}

// Register in your startup
builder.Services
    .AddApiAuthentication()
    .WithKeyScheme<MyApiKeyService>("X-API-Key", "ApiKey");
```

#### Using Inline Delegate

```csharp
builder.Services
    .AddApiAuthentication()
    .WithKeyScheme("X-API-Key", async (key) => {
        // Validate key against database or other source
        bool isValid = key == "valid-api-key-123";
        return new AuthResponse(isValid);
    }, "ApiKey");
```

### Custom Claim Types

The library supports various claim value types including:

- String (default)
- Integer
- Boolean
- DateTime
- JsonArray (for serialized arrays)
- JsonObject (for serialized objects)

Example of creating claims with different types:

```csharp
var claims = new List<CustomClaim>
{
    new("sub", userId, CustomClaimValueTypes.String, isUniqueId: true),
    new("email", userEmail),
    new("is_admin", isAdmin.ToString(), CustomClaimValueTypes.Boolean),
    new("created_at", DateTime.UtcNow.ToString("o"), CustomClaimValueTypes.DateTime),
    new("roles", JsonSerializer.Serialize(userRoles), CustomClaimValueTypes.JsonArray)
};

var tokenResponse = await currentUser.GenerateJwt(claims);
```

## 🔄 Multiple Authentication Schemes

You can combine multiple authentication schemes to support different client types. The library now supports **fluent chaining** for easy configuration:

```csharp
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(builder.Configuration.GetRequiredSection<JwtConfiguration>(nameof(JwtConfiguration)))
    .WithBasicScheme(async (username, password) => {
        // Your authentication logic here
        bool isValid = username == "admin" && password == "password123";
        return new AuthResponse(isValid);
    }, "Basic")
    .WithKeyScheme("X-API-Key", async (key) => {
        // Validate key against database or other source
        bool isValid = key == "valid-api-key-123";
        return new AuthResponse(isValid);
    }, "ApiKey");
```

### Flexible Combinations

You can use any combination of authentication schemes in any order:

```csharp
// JWT + Basic only
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(jwtConfig)
    .WithBasicScheme(authFunc);

// Basic + API Key only  
builder.Services
    .AddApiAuthentication()
    .WithBasicScheme(authFunc)
    .WithKeyScheme("X-API-Key", keyFunc, "ApiKey");

// All three schemes
builder.Services
    .AddApiAuthentication()
    .WithJwtBearer(jwtConfig)
    .WithBasicScheme(authFunc)
    .WithKeyScheme("X-API-Key", keyFunc, "ApiKey");
```

### Using Multiple Schemes in Controllers

Then in your controllers or actions, specify which schemes to accept:

```csharp
// Accept any of the configured schemes
[Authorize(AuthenticationSchemes = "Bearer,Basic,ApiKey")]
public class SecureController : ControllerBase
{
    // Protected endpoints
}

// Or require specific schemes for specific endpoints
[Authorize(AuthenticationSchemes = "Bearer")]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpGet]
    public IActionResult GetUserProfile() { /* ... */ }

    [HttpPost("admin")]
    [Authorize(AuthenticationSchemes = "Basic,ApiKey")]
    public IActionResult AdminAction() { /* ... */ }
}
```

### Minimal API with Multiple Schemes

For Minimal APIs, you can use the `RequireAuthorization` extension with specific schemes:

```csharp
// JWT only endpoint
app.MapGet("/jwt-only", () => "JWT access granted")
   .RequireAuthorization(policy => policy.RequireAuthenticationSchemes("Bearer"));

// Basic auth only endpoint  
app.MapGet("/basic-only", () => "Basic access granted")
   .RequireAuthorization(policy => policy.RequireAuthenticationSchemes("Basic"));

// Multiple schemes allowed
app.MapGet("/multi-auth", () => "Multi-auth access granted")
   .RequireAuthorization(); // Accepts any configured scheme
```

### Complete Working Example

See the [SampleApiWithMultipleAuth](sample/SampleApiWithMultipleAuth/) project for a complete working example that demonstrates:
- JWT Bearer authentication
- Basic authentication  
- API Key authentication
- Endpoints that accept specific schemes
- Endpoints that accept multiple schemes
- Swagger UI configuration for all schemes

## 🔒 Security Best Practices

### JWT Security

1. **Secret Key Management**
   - Use a strong secret key (at least 256 bits)
   - Store secrets in secure locations (Azure Key Vault, AWS Secrets Manager)
   - Use user secrets or environment variables during development

2. **Token Configuration**
   - Set appropriate token expiration times
   - Implement token validation and revocation when needed
   - Use HTTPS for all authenticated endpoints

3. **Claims and Scopes**
   - Include only necessary claims in tokens
   - Implement proper role/scope-based authorization

### Basic Authentication

1. **Transport Security**
   - Always use HTTPS
   - Consider this only for development or secure internal services

2. **Credential Storage**
   - Never store plain-text passwords
   - Implement proper password hashing (bcrypt, Argon2, etc.)

### API Key Security

1. **Key Management**
   - Generate strong, random keys
   - Assign one key per client
   - Implement key rotation policies

2. **Access Control**
   - Implement rate limiting
   - Define specific permissions per key
   - Log and monitor key usage

## 📖 Additional Configuration

### Using Custom JWT Claim Providers

Implement custom claim generation logic by creating a service that provides claims during token creation.

### Refresh Token Implementation

Implement secure refresh token rotation to maintain long-term sessions without compromising security.

### Integrating with Identity Providers

Configure the JWT authentication to work with external identity providers like Azure AD, Auth0, or custom OIDC providers.

## 📋 Troubleshooting

### Common Issues

1. **401 Unauthorized Responses**
   - Check if the authentication scheme is properly registered
   - Verify credentials or tokens are being sent correctly
   - Ensure your scheme name matches in both configuration and Authorize attributes

2. **Token Validation Failures**
   - Check issuer and audience settings
   - Verify the token is not expired
   - Ensure the signature key is correct

## 📝 License

This library is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
