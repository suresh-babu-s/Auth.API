using System;
using System.Linq;
using System.Web.Http.Controllers;
using System.IdentityModel.Tokens;
using System.Configuration;
using System.Security.Cryptography;

namespace B2CAuth.Lib.Filters
{
    public class B2CAuthorizationFilterAttribute : System.Web.Http.Filters.ActionFilterAttribute
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

        public B2CAuthorizationFilterAttribute(string userRole)
        {
            _customRole = userRole;
        }

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            string email = string.Empty;
            const string EMAIL = "email";

            string tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImhqWWRETF9PbDFKZkFwLXZDZUwtU21nb3U5MnNhVE41a2ZWOTd1amFQT2sifQ.eyJleHAiOjE2NTQyNDY3MzYsIm5iZiI6MTY1NDE2MDMzNiwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9hZGIyY2N1c3RvbWdtYWlsLmIyY2xvZ2luLmNvbS9iN2YwNGI4MS0zODI2LTQ0ZWUtOGM5NS0xOWEwMmQ1NzAzMTQvdjIuMC8iLCJzdWIiOiJkZDgxODc1Ny1iNWFkLTQ5MTItYTVkMS0xMGQ1YmRjMTA2N2UiLCJhdWQiOiI3ODdlZDA3YS1kZGRiLTQxMmYtOWI0Yy1jMTcxMDdjZTUxMjMiLCJub25jZSI6ImRlZmF1bHROb25jZSIsImlhdCI6MTY1NDE2MDMzNiwiYXV0aF90aW1lIjoxNjU0MTYwMzM2LCJlbWFpbCI6InNzdXJlc2hiYWJ1MjAxNEBnbWFpbC5jb20iLCJnaXZlbl9uYW1lIjoic3VyZXNoIGJhYnUiLCJmYW1pbHlfbmFtZSI6InMiLCJuYW1lIjoiU3VyZXNoIEJhYnUiLCJpZHAiOiJnb29nbGUuY29tIiwicm9sZSI6InNzdXJlc2hiYWJ1MjAxNEBnbWFpbC5jb20iLCJ0aWQiOiJiN2YwNGI4MS0zODI2LTQ0ZWUtOGM5NS0xOWEwMmQ1NzAzMTQifQ.IyqiJ6RyExGzm-Tj0CzeGsPdN0ZEDsspV9MZoESi6w6pcWZxwvDaAph7YPtQfTBQ5DAlp0p52jQ2TXLalg1O-nX3D-L1srZXkRnNopdjjcAeVVhgz2rMqYGDSY4l1uRdJfsO0wt4bQEfW7rUfC1iaMlFA6L4JP6RUNbNHfdyN-yzV7G4Oml1mmNThhEXk5cU805LHvLxrJrYwPceUTyENhQ_uqXU0FJ3AfPugm-RFHWQPcpgsvLcnW6phTXGNAoDzKbtzf-oa4JxfrXg585pEBcTIlnRj7Ng25qAmXoMpOsY58t23kmLhW_z_FRm0hF1-PbgdHeDgb8tNZBpIl6_1Q";
            string issuer = "https://adb2ccustomgmail.b2clogin.com/b7f04b81-3826-44ee-8c95-19a02d570314/v2.0/";
            string audience = "787ed07a-dddb-412f-9b4c-c17107ce5123";

            string modulus = "wWV1Mnth78SXaFbm43jQnU-aWLhjZdTLZWGvt-2AC0tQblM2YabP3VuI6yqRcnD42cTRoO2C8oSSDwn-L7OJcDa8XWzWXO_C2_cXAvGfsyFqRGiw-Hh5S8x98p7-ed-Yyfc4iHTZ4z9TD5MifYDNFbQpds5h5-6S8TWHG0JadcmHQdHb4Bqmg10kRdLt4pIgUy-tqIr9XReYREIg6tMJnBrTAPB-sS4V5ujUsd0DZhVDhAI17EZEwoMtmEbuBG9f95MfuTul4DihWZ7oHVMglz1e0ztN5BvqS5HsKnbTJUCQXuDr0Qbx0AzEDOBuVS4-fUbu6Lo27TbRYGGidvjPXQ";
            string exponent = "AQAB";

            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            }
            else
            {
                string authenticationToken = actionContext.Request.Headers.Authorization.Parameter;
                var token = new JwtSecurityToken(authenticationToken);

                if (ValidateCurrentToken(tokenStr, modulus, exponent, issuer, audience))
                {
                    email = token.Claims.First(claim => claim.Type.ToLower() == EMAIL).Value;

                    //to do
                    //get role of user using above email id and validate with the role in the ActionFilterAttribute

                    //for testing - To be modified after fetching roles from the database
                    if (email == "ssureshbabu2014@gmail.com")
                    {
                        if (!_customRole.Equals("CanDoAnything"))
                        {
                            actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
                        }
                    }
                    else if (email == "srajn2022@gmail.com")
                    {
                        if (!_customRole.Equals("NeedAdminRights"))
                        {
                            actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
                        }
                    }
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
                      //Modulus = FromBase64Url("wWV1Mnth78SXaFbm43jQnU-aWLhjZdTLZWGvt-2AC0tQblM2YabP3VuI6yqRcnD42cTRoO2C8oSSDwn-L7OJcDa8XWzWXO_C2_cXAvGfsyFqRGiw-Hh5S8x98p7-ed-Yyfc4iHTZ4z9TD5MifYDNFbQpds5h5-6S8TWHG0JadcmHQdHb4Bqmg10kRdLt4pIgUy-tqIr9XReYREIg6tMJnBrTAPB-sS4V5ujUsd0DZhVDhAI17EZEwoMtmEbuBG9f95MfuTul4DihWZ7oHVMglz1e0ztN5BvqS5HsKnbTJUCQXuDr0Qbx0AzEDOBuVS4-fUbu6Lo27TbRYGGidvjPXQ"),
                      Modulus = FromBase64Url(modulus),
                      //Exponent = FromBase64Url("AQAB")
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