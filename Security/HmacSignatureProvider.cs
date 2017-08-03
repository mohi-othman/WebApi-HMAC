using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Tools.WebAPI.Security
{
    /// <summary>
    /// Secure signature provider for the Web API using the HMAC schema
    /// </summary>
    public class HmacSignatureProvider : ISignatureProvider
    {
        /// <summary>
        /// Name of the header used to store the User ID
        /// </summary>
        public string UserIDHeader { get { return "WebAPI-Security-HMAC-UserID"; } }

        /// <summary>
        /// Name of the authentication scheme used by this provider
        /// </summary>
        public string SignatureScheme { get { return "WebAPI-Security-HMAC-Scheme"; } }

        /// <summary>
        /// Create a signature token
        /// </summary>
        /// <param name="Request">The HttpRequestMessage object the signature is created for</param>
        /// <param name="secretKey">Secret key for hashing the signature</param>
        /// <param name="stripProtocol">Strip the protocol part of the URI when creating signature. Default is false.</param>
        /// <returns>Signature</returns>
        public string CreateSignature(HttpRequestMessage Request, string secretKey, bool stripProtocol = false)
        {
            if (Request.Headers.Date == null)
                throw new ApplicationException("Header must contain date");

            return CreateSignature(Request.Method.Method,
                Request.RequestUri.ToString().ToLower(),
                (DateTimeOffset)Request.Headers.Date,
                Request.Content != null ? Request.Content.ReadAsStringAsync().Result : "",
                secretKey,
                stripProtocol
                 );
        }

        /// <summary>
        /// Create a signature token
        /// </summary>
        /// <param name="HttpMethod">The HTTP method for the request</param>
        /// <param name="RequestUri">The request URI</param>
        /// <param name="RequestDate">Date of the request (UTC)</param>
        /// <param name="RequestContent">Content of the request</param>
        /// <param name="secretKey">Secret key for hashing the signature</param>
        /// <param name="stripProtocol">Strip the protocol part of the URI when creating signature. Default is false.</param>
        /// <returns>Signature</returns>
        public string CreateSignature(string HttpMethod, string RequestUri, DateTimeOffset RequestDate, string RequestContent, string secretKey, bool stripProtocol = false)
        {
            if (string.IsNullOrWhiteSpace(secretKey))
                throw new ApplicationException("User has no secret key");

            if (stripProtocol)
            {
                RequestUri = RequestUri.ToLowerInvariant().Replace("http:", "").Replace("https:", "");
            }

            var unhashedString = string.Concat(HttpMethod.ToLowerInvariant(), RequestUri.ToLowerInvariant(), RequestDate.ToUniversalTime().ToString("r"), RequestContent);
            var hashedString = "";
            using (var hashProvider = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                var hashBytes = hashProvider.ComputeHash(Encoding.UTF8.GetBytes(unhashedString));
                hashedString = Convert.ToBase64String(hashBytes);
            }
            return hashedString;
        }

        /// <summary>
        /// Adds a signature to the supplied HttpRequestMessage object
        /// </summary>
        /// <param name="Request">HttpRequestMessage object</param>
        /// <param name="UserId">Unique user ID</param>
        /// <param name="SecretKey">Secret key for hashing the signature</param>
        /// <param name="stripProtocol">Strip the protocol part of the URI when creating signature. Default is false.</param>
        /// <returns>Modified HttpRequestMessage object</returns>
        public HttpRequestMessage AddSignature(HttpRequestMessage Request, string UserId, string SecretKey, bool stripProtocol = false)
        {
            if (Request.Headers.Date == null)
                Request.Headers.Date = DateTimeOffset.UtcNow;

            var signature = CreateSignature(Request, SecretKey, stripProtocol);

            Request.Headers.Authorization = new AuthenticationHeaderValue(SignatureScheme, signature);

            if (!Request.Headers.Contains(UserIDHeader))
            {
                Request.Headers.Add(UserIDHeader, UserId);
            }

            return Request;
        }

        /// <summary>
        /// Validates if a Request has a valid signature
        /// </summary>
        /// <param name="Request">The HttpRequestMessage to be validated</param>
        /// <param name="UserId">Unique user ID</param>
        /// <param name="SecretKey">Secret key for hashing the signature</param>
        /// <param name="TimeOutPeriod">How long before the signature expires in seconds</param>
        /// <param name="stripProtocol">Strip the protocol part of the URI when creating signature. Default is false.</param>
        /// <returns></returns>
        public bool HasValidSignature(HttpRequestMessage Request, string UserId, string SecretKey, int TimeOutPeriod, bool stripProtocol = false)
        {
            if (Request.Headers.GetValues(UserIDHeader) == null ||
                Request.Headers.GetValues(UserIDHeader) == null ||
                Request.Headers.GetValues(UserIDHeader).First() != UserId ||
                Request.Headers.Authorization == null ||
                Request.Headers.Authorization.Scheme != SignatureScheme ||
                string.IsNullOrEmpty(Request.Headers.Authorization.Parameter) ||
                Request.Headers.Date == null ||
                Request.Headers.Date.Value.ToUniversalTime().AddSeconds(TimeOutPeriod) < DateTime.Now.ToUniversalTime())
                return false;

            var assignedSignature = Request.Headers.Authorization.Parameter;
            var computedSignature = CreateSignature(Request, SecretKey, stripProtocol);

            return assignedSignature == computedSignature;
        }
    }
}
