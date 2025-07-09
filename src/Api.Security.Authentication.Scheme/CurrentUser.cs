using Api.Security.Authentication.Core;
using Microsoft.AspNetCore.Http;

namespace Api.Security.Authentication.Scheme;

public class CurrentUser(IHttpContextAccessor context) : ClaimResolver(context), ICurrentUser
{
    
}