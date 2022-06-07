using System;
using System.Web.Http.Controllers;
using System.Configuration;
using System.Diagnostics;
using System.Threading.Tasks;

namespace B2CAuth.Api.Filters
{
    public class B2CAuthorizeAttribute : System.Web.Http.AuthorizeAttribute
    {
        private string _customRole = string.Empty;

        private static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string signUpPolicy = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        private static string signInPolicy = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        private static string editProfilePolicy = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        private static string _audience = ConfigurationManager.AppSettings["ida:Audience"];
        private static string _issuer = ConfigurationManager.AppSettings["ida:Issuer"];

        private static string _modulus = ConfigurationManager.AppSettings["ida:Modulus"];
        private static string _exponent = ConfigurationManager.AppSettings["ida:Exponent"];

        private static string _jwtValidationApp = ConfigurationManager.AppSettings["JwtValidationApp"];

        public B2CAuthorizeAttribute(string userRole)
        {
            _customRole = userRole;
        }

        public override Task OnAuthorizationAsync(HttpActionContext actionContext, System.Threading.CancellationToken cancellationToken)
        {
            string authenticationToken = string.Empty;
            bool isValidToken = false;

            if (actionContext.Request.Headers.Authorization != null)
            {
                authenticationToken = actionContext.Request.Headers.Authorization.Parameter;
                isValidToken = ValidateCurrentTokenByConsole(authenticationToken, _modulus, _exponent, _issuer, _audience);
            }

            //User is Authorized, complete execution
            if (isValidToken)
            {
                return Task.FromResult<object>(null);
            }
            else
            {
                actionContext.Response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
                return Task.FromResult<object>(System.Net.HttpStatusCode.Unauthorized);
            }
        }

        private bool ValidateCurrentTokenByConsole(string token, string modulus, string exponent, string issuerStr, string audienceStr)
        {
            bool isValid = false;
            const int SUCCESS_CODE = 1;
            string args = token + " " + issuerStr + " " + audienceStr + " " + modulus + " " + exponent;
            try
            {
                Process process = Process.Start(@_jwtValidationApp, args);
                process.WaitForExit();
                isValid = process.ExitCode.Equals(SUCCESS_CODE);
                Debug.Print("Exit code -> " + process.ExitCode.ToString());
            }
            catch (Exception ex)
            {
                Debug.Print("Error while calling signature checking process -> " + ex.ToString());
            }
            return isValid;
        }
    }
}