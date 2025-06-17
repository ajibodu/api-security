namespace Api.Authorization;

public class ClaimPolicyConfig
{
    public string ClaimType { get; set; }
    public string[] RequiredValues { get; set; } = [];
}