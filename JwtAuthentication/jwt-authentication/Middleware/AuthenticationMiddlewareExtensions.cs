using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using Authentication.Jwt.Middleware;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Jwt.Extensions
{
    public static class AuthenticationMiddlwareExtensions
    {
        public static void UseJwtAuthentication(this IApplicationBuilder app,TokenProviderOptions tokenProviderOptions)
        {          
            app.UseMiddleware<TokenProviderMiddleware>(Options.Create(tokenProviderOptions));
        }       
    }
}
