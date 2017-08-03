using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.IO;
using System.Reflection;

namespace Tools.WebAPI.Security.Server
{
    public class WebConfigSecretProvider : ISecretProvider
    {
        private const string _defaultSecretKeySection = "ApiSecretKeys";
        
        public string GetSignatureSecretKey(string UserId)
        {
            return GetSignatureSecretKey(UserId, _defaultSecretKeySection);
        }
        
        public string GetSignatureSecretKey(string UserId, string SecretKeySection)
        {
            var secret = "";
            var keySection = (NameValueCollection)ConfigurationManager.GetSection(SecretKeySection);

            if (keySection.AllKeys.Contains(UserId))
            {
                secret = keySection[UserId];
            }

            return secret;
        }


        public List<string> GetProtocolStripList()
        {
            var list = string.IsNullOrEmpty(ConfigurationManager.AppSettings["HmacProtocolStripList"]) 
                ? new List<string>()
                : ConfigurationManager.AppSettings["HmacProtocolStripList"].Split(',').ToList();

            return list;
        }
    }
}
