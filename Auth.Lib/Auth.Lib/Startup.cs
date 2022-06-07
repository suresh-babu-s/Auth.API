using B2CAuth.Lib.App_Start;
using B2CAuth.Lib.Helpers;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace B2CAuth.Lib
{
    public class Startup
    {
        // These values are pulled from web.config
        public static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        public static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string signUpPolicy = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string signInPolicy = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string editProfilePolicy = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public static string audience = ConfigurationManager.AppSettings["ida:Audience"];
        public static string issuer = ConfigurationManager.AppSettings["ida:Issuer"];

        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();

            ConfigureOAuth(app);

            app.UseWebApi(config);
            //app.UseJwtBearerAuthentication(
            //    new JwtBearerAuthenticationOptions
            //    {
            //        AuthenticationMode = AuthenticationMode.Active,
            //        TokenValidationParameters = new TokenValidationParameters()
            //        {
            //            //ValidAudience = ConfigHelper.GetAudience(),
            //            ValidAudience = audience,
            //            //ValidIssuer = ConfigHelper.GetIssuer(),
            //            ValidIssuer = issuer,
            //            IssuerSigningKey = ConfigHelper.GetSymmetricSecurityKey(),
            //            ValidateLifetime = true,
            //            ValidateIssuerSigningKey = true
            //        }
            //    });
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(signUpPolicy));
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(signInPolicy));
            app.UseOAuthBearerAuthentication(CreateBearerOptionsFromPolicy(editProfilePolicy));
        }

        private OAuthBearerAuthenticationOptions CreateBearerOptionsFromPolicy(string policy)
        {
            var metadataEndpoint = string.Format(aadInstance, tenant, policy);

            TokenValidationParameters tvps = new TokenValidationParameters
            {
                // This is where you specify that your API only accepts tokens from its own clients
                ValidAudience = clientId,
                AuthenticationType = policy,
                NameClaimType = "http://schemas.microsoft.com/identity/claims/objectidentifier"
            };

            return new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(tvps, new OpenIdConnectCachingSecurityTokenProvider(metadataEndpoint))
            };
        }
    }
}