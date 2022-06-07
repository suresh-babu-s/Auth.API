using System;
using System.Linq;
using System.Web.Http.Controllers;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Configuration;

namespace Auth.Library.Filters
{
    public class B2CActionFilterAttribute : System.Web.Http.Filters.ActionFilterAttribute
    {
        private string _customRole = string.Empty;

        public static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string signUpPolicy = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string signInPolicy = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string editProfilePolicy = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public static string _audience = ConfigurationManager.AppSettings["ida:Audience"];
        public static string _issuer = ConfigurationManager.AppSettings["ida:Issuer"];

        static string _modulus = ConfigurationManager.AppSettings["ida:Modulus"];
        static string _exponent = ConfigurationManager.AppSettings["ida:Exponent"];

        public B2CActionFilterAttribute(string userRole)
        {
            _customRole = userRole;
        }

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            }
            else
            {
                string authenticationToken = string.Empty;
                authenticationToken = actionContext.Request.Headers.Authorization.Parameter;

                if (!ValidateCurrentToken(authenticationToken, _modulus, _exponent, _issuer, _audience))
                {
                    actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
                }
            }
        }

        /// <summary>
        /// Validate current JWT token by verifying the signature, issuer and audience. 
        /// Once it has been varified, also check whether current user has beeen authenticated or not.
        /// </summary>
        /// <param name="token">JWT token to be validated.</param>
        /// <param name="modulus">RSA modulus for generating the signing key.</param>
        /// <param name="exponent">RSA exponent for generating the signing key.</param>
        /// <param name="issuer">Name of the token issuer for validating.</param>
        /// <param name="audience">Name of the audience for validating.</param>
        /// <returns>True if the token has been validated successfully else false.</returns>
        private bool ValidateCurrentToken(string token, string modulus, string exponent, string issuer, string audience)
        {
            bool isSuccess = false;

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
                var claimPrincipal = handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
                //JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;
                isSuccess = claimPrincipal.Identity.IsAuthenticated;
            }
            catch (Exception ex)
            {
                //log exception

                isSuccess = false;
            }
            return isSuccess;
        }

        private byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0 ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/").Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }

}