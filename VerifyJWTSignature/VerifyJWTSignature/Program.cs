using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VerifyJWTSignature
{
    class Program
    {
        public static int Main(string[] args)
        {
            int returnValue = 0;

            string tokenStr = args[0];
            string issuer = args[1];
            string audience = args[2];
            string modulus = args[3];
            string exponent = args[4];

            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(
                  new RSAParameters()
                  {
                        Modulus = FromBase64Url(modulus),
                        Exponent = FromBase64Url(exponent)
                  });

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = new RsaSecurityKey(rsa)
                };

                SecurityToken validatedSecurityToken = null;
                var handler = new JwtSecurityTokenHandler();
                var claimPrincipal = handler.ValidateToken(tokenStr, validationParameters, out validatedSecurityToken);
                if (claimPrincipal.Identity.IsAuthenticated)
                {
                    JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;
                    //validation successful. So return 1
                    returnValue = 1;
                    Console.WriteLine("Token validated successfully! JWT Token signing key : " + validatedJwt.SigningKey.ToString());
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error -> " + ex.Message);
            }

            return returnValue;
            //Console.Read();
        }

        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0 ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }
}
