using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
﻿using System.Security.Claims;
using System.Security.Principal;
using Tools.WebAPI.Security;

namespace Tools.WebAPI.Security.Server
{
    /// <summary>
    /// Base class for HMAC authentication attributes
    /// </summary>
    public abstract class HmacBaseAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        protected abstract ISecretProvider SecretProvider { get; }      // Retrieves implementation of the secret key provider
        protected abstract ISignatureProvider SignatureProvider { get; }// Retrieves implementation of the signature provider
        protected abstract int TimeOutPeriod { get; }                   // Retrieves signature timeout in seconds
        protected abstract bool IsHmacEnabled { get; }                  // If true HMAC authentication is applied, otherwise it is bypassed (to be used for debugging)
        
        public string Realm { get; set; }

        public Task AuthenticateAsync(HttpAuthenticationContext context, System.Threading.CancellationToken cancellationToken)
        {
            if (!IsHmacEnabled)
            {
                var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, "0")
                };

                context.Principal = new ClaimsPrincipal(
                    new[]{
                    new ClaimsIdentity(claims, SignatureProvider.SignatureScheme)
                });
                return Task.FromResult(0);
            }

            var request = context.Request;
            var authorization = request.Headers.Authorization;
            
            if (authorization == null || authorization.Scheme != SignatureProvider.SignatureScheme)
            {
                return Task.FromResult(0);
            }
            if (string.IsNullOrWhiteSpace(authorization.Parameter))
            {
                context.ErrorResult = new AuthenticationFailureResult("Authorization token missing from header", request);
                return Task.FromResult(0);
            }
            if (!request.Headers.Contains(SignatureProvider.UserIDHeader))
            {
                context.ErrorResult = new AuthenticationFailureResult(string.Format("User ID header {0} missing", SignatureProvider.UserIDHeader), request);
                return Task.FromResult(0);
            }
            var userId = request.Headers.GetValues(SignatureProvider.UserIDHeader).FirstOrDefault();
            if (string.IsNullOrEmpty(userId))
            {
                context.ErrorResult = new AuthenticationFailureResult(string.Format("User ID missing from header value {0}", SignatureProvider.UserIDHeader), request);
                return Task.FromResult(0);
            }

            var key = SecretProvider.GetSignatureSecretKey(userId);
            
            if (string.IsNullOrEmpty(key))
            {
                context.ErrorResult = new AuthenticationFailureResult("Unknown User ID", request);
                return Task.FromResult(0);
            }

            var uri = request.RequestUri.ToString().ToLowerInvariant();
            var stripProtocol = SecretProvider.GetProtocolStripList().Any(site => uri.Contains(site));
            var success = SignatureProvider.HasValidSignature(request, userId, key, TimeOutPeriod, stripProtocol);
            
            //success = true;

            if (!success)
            {
                var sig = SignatureProvider.CreateSignature(request, key, stripProtocol);
                var diagnostic = string.Format("Diagnostic info follows. Signature: {0}, attached sig: {1}, method: {2}, URI: {3}, content: {4}, Request time stamp:{5}, Server time stamp:{6}, User: {7}, Auth: {8}",
                        sig,
                        request.Headers.Authorization.Parameter,
                        request.Method,
                        request.RequestUri,
                        request.Content != null ? request.Content.ReadAsStringAsync().Result : "",
                        request.Headers.Date == null ? "" : request.Headers.Date.Value.ToUniversalTime().ToString("r"),
                        DateTime.Now.ToUniversalTime().ToString("r"), 
                        request.Headers.GetValues(SignatureProvider.UserIDHeader).FirstOrDefault(),
                        request.Headers.Authorization.Scheme);
                context.ErrorResult = new AuthenticationFailureResult("Invalid or expired signature. " + diagnostic, request);
            }
            else
            {
                var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, userId)
                };

                context.Principal = new ClaimsPrincipal(
                    new[]{
                    new ClaimsIdentity(claims, SignatureProvider.SignatureScheme)
                });

            }

            //Place user id in context for later use
            context.ActionContext.Request.Properties.Add(UserIdField, userId);

            return Task.FromResult(0);
        }

        public Task ChallengeAsync(System.Web.Http.Filters.HttpAuthenticationChallengeContext context, System.Threading.CancellationToken cancellationToken)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            string parameter;

            if (String.IsNullOrEmpty(Realm))
            {
                parameter = null;
            }
            else
            {
                parameter = "realm=\"" + Realm + "\"";
            }

            var challenge = new System.Net.Http.Headers.AuthenticationHeaderValue(SignatureProvider.SignatureScheme, parameter);

            context.Result = new AddChallengeOnUnauthorizedResult(challenge, context.Result);
            return Task.FromResult(0);
        }

        public bool AllowMultiple
        {
            get { return false; }
        }

        public static string UserIdField = "WebApiUserId";
    }
}
