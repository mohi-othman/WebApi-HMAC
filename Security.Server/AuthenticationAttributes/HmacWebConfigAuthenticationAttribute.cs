using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;

namespace Tools.WebAPI.Security.Server
{
    /// <summary>
    /// Passes request through the HMAC authentication process backed by the UserID/SecretKey store in Web.Config
    /// </summary>
    public class HmacWebConfigAuthenticationAttribute : HmacBaseAuthenticationAttribute
    {
        private const string HMAC_SIGNATURE_TIMEOUT = "HmacSignatureTimeout";
        private const string HMAC_ENABLED = "HmacSecurityEnabled";

        private bool? isHmacEnabled = null;
        private int? timeOurPeriod = null;

        protected override bool IsHmacEnabled
        {
            get
            {
                if (isHmacEnabled == null)
                {
                    if (ConfigurationManager.AppSettings.AllKeys.Contains(HMAC_ENABLED) &&
                        ConfigurationManager.AppSettings[HMAC_ENABLED].ToLowerInvariant() == "false")
                    {
                        isHmacEnabled = false;
                    }
                    else
                    {
                        isHmacEnabled = true;
                    }
                }
                return (bool)isHmacEnabled;
            }
        }

        protected override ISecretProvider SecretProvider
        {
            get { return new WebConfigSecretProvider(); }
        }

        protected override ISignatureProvider SignatureProvider
        {
            get
            {
                return new HmacSignatureProvider();
            }
        }

        protected override int TimeOutPeriod
        {
            get
            {
                if (timeOurPeriod == null)
                {
                    var timeOut = 600;  //Default value
                    if (ConfigurationManager.AppSettings.AllKeys.Contains(HMAC_SIGNATURE_TIMEOUT))
                    {
                        Int32.TryParse(ConfigurationManager.AppSettings[HMAC_SIGNATURE_TIMEOUT], out timeOut);
                    }
                    timeOurPeriod = timeOut;
                }
                return (int)timeOurPeriod;
            }
        }
    }
}
