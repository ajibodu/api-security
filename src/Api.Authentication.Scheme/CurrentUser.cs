using Api.Authentication.Core;
using Microsoft.AspNetCore.Http;

namespace Api.Authentication.Scheme;

public class CurrentUser(IHttpContextAccessor context) : ClaimResolver(context), ICurrentUser
{
    
}