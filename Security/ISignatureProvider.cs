using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Tools.WebAPI.Security
{
    public interface ISignatureProvider
    {
        string UserIDHeader { get; }

        string SignatureScheme { get; }

        string CreateSignature(HttpRequestMessage Request, string secretKey, bool stripProtocol);

        string CreateSignature(string HttpMethod, string RequestUri, DateTimeOffset RequestDate, string RequestContent, string secretKey, bool stripProtocol);

        HttpRequestMessage AddSignature(HttpRequestMessage Request, string UserId, string SecretKey, bool stripProtocol);

        bool HasValidSignature(HttpRequestMessage Request, string UserId, string SecretKey, int TimeOutPeriod, bool stripProtocol);
    }
}
