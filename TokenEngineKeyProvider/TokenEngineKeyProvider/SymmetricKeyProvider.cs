using KeePassLib.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TokenEngineKeyProvider
{
    class SymmetricKeyProvider : KeyProvider
    {
        private IPlugin plugin;

        public SymmetricKeyProvider(IPlugin plugin)
            => this.plugin = plugin ?? throw new ArgumentNullException(nameof(plugin));

        public override string Name => "Token Engine Key Provider";

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            throw new NotImplementedException();
        }
    }
}
