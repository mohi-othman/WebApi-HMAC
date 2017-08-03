using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Tools.WebAPI.Security.Server
{
    public class HmacHelper
    {
        /// <summary>
        /// Use this method to generate random HMAC key
        /// </summary>
        /// <returns></returns>
        public static string GenerateHmacKey()
        {
            var rng = RandomNumberGenerator.Create();
            var data = new byte[64];
            rng.GetBytes(data);
            return Convert.ToBase64String(data);
        }
    }
}
