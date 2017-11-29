using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Jwt
{
    public static class Configuration
    {
        public static void AddJwtAuthentication(this IServiceCollection services,TokenValidationParameters tokenValidationParameters)
        {            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {                    
                    options.TokenValidationParameters = tokenValidationParameters;                   
                });
        }
    }
}
