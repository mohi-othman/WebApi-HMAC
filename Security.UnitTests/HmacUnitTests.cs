using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Tools.WebAPI.Security.UnitTests
{
    [TestClass]
    public class HmacUnitTests
    {
        private string GenerateHmacKey()
        {
            var rng = RandomNumberGenerator.Create();
            var data = new byte[64];
            rng.GetBytes(data);
            return Convert.ToBase64String(data);
        }

        [TestMethod]
        public void TestValidRequest()
        {
            var key = GenerateHmacKey();
            var user = "test";
            var json = "{'test':'1'}";
            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.Tools.com/apr/something");
            var content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
            var hmacProvider = new Tools.WebAPI.Security.HmacSignatureProvider();
            var signedRequest = hmacProvider.AddSignature(request, user, key);
            Assert.IsTrue(hmacProvider.HasValidSignature(signedRequest, user, key, 600));
        }

        [TestMethod]
        public void TestExpiredRequest()
        {
            var key = GenerateHmacKey();
            var user = "test";
            var json = "{'test':'1'}";
            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.Tools.com/apr/something");
            var content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
            request.Headers.Date = DateTimeOffset.UtcNow.AddMinutes(-11);
            var hmacProvider = new Tools.WebAPI.Security.HmacSignatureProvider();            
            var signedRequest = hmacProvider.AddSignature(request, user, key);
            Assert.IsFalse(hmacProvider.HasValidSignature(signedRequest, user, key, 600));
        }
       
    }
}
