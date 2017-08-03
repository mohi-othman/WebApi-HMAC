using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tools.WebAPI.Security.Server
{
    public interface ISecretProvider
    {
        string GetSignatureSecretKey(string UserId);

        List<string> GetProtocolStripList();
    }
}
