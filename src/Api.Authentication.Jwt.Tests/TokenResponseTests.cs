using System.Collections.Generic;
using Api.Authentication.Jwt.Models;
using Xunit;

namespace Api.Authentication.Jwt.Tests;

public class TokenResponseTests
{
    [Fact]
    public void TokenResponse_Properties_AreSetCorrectly()
    {
        var response = new TokenResponse("jwt-token", 30);
        Assert.Equal("jwt-token", response.Jwt);
        Assert.Equal(30, response.ExpirationInMinutes);
    }
}
