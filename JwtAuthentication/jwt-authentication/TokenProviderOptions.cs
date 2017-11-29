using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Nova.Authentication.Jwt
{
    public class TokenProviderOptions
    {
        /// <summary>
        ///  relative path to listen on for token
        /// </summary>
        public string Path { get; set; } = "/token";

        /// <summary>
        /// The issuer (iss) claim for generated tokens
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Intended audience for the token.
        /// aud claim of the generated token
        /// </summary>
        public string Audience { get; set; }
        
        /// <summary>
        /// Expiration time for the generated token
        /// </summary>
        public TimeSpan Expiration { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// The signing key to use when generating tokens.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// resolves a user identity w.r.t given username and password
        /// </summary>
        public Func<string,string,Task<ClaimsIdentity>> IdentityResolver { get; set; }

        /// <summary>
        /// Generates a random value (nonce) for each generated token.
        /// </summary>
        /// <remarks>The default nonce is a random GUID.</remarks>
        public Func<Task<string>> NonceGenerator { get; set; }
            = () => Task.FromResult(Guid.NewGuid().ToString());

    }
}
