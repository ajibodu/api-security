using System.Threading.Tasks;
using Api.Authentication.Jwt.Models;
using Xunit;

namespace Api.Authentication.Jwt.Tests;

public class CustomClaimTests
{
    [Fact]
    public void CustomClaim_Properties_AreSetCorrectly()
    {
        var claim = new CustomClaim("type", "value", CustomClaimValueTypes.String, true);
        Assert.Equal("type", claim.Type);
        Assert.Equal("value", claim.Value);
        Assert.Equal(CustomClaimValueTypes.String, claim.ValueType);
        Assert.True(claim.IsUniqueId);
    }

    [Fact]
    public void CustomClaim_DefaultValueType_IsString()
    {
        var claim = new CustomClaim("type", "value");
        Assert.Equal(CustomClaimValueTypes.String, claim.ValueType);
    }
}
