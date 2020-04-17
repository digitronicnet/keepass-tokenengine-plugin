using KeePass.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TokenEngineKeyProvider
{
    public sealed class TokenEngineKeyProviderExt : Plugin
    {
        public override bool Initialize(IPluginHost host)
        {
            return true;
        }
    }
}
