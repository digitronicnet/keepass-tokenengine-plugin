using KeePassLib.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TokenEngineKeyProvider
{
    class SymmetricKeyProvider : KeyProvider
    {
        private const string label = "keepasskey";
        private IPlugin plugin;

        public SymmetricKeyProvider(IPlugin plugin)
            => this.plugin = plugin ?? throw new ArgumentNullException(nameof(plugin));

        public override string Name => "Token Engine Key Provider";

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            try
            {
                var tokenList = plugin.TokenEngine.GetTokenListAsync().Result;

                foreach (var token in tokenList)
                {
                    token.LoadAsync().Wait();
                    if (!token.Capability.IsInitialized)
                        continue;

                    var dataObject = token.FindObjectsAsync(label, isPrivate: true)
                        .Result
                        .FirstOrDefault();

                    if (dataObject == null)
                        continue;

                    var data = dataObject.GetDataAsync().Result;

                    try
                    {
                        using (var symmetricKeyData = SymmetricKeyData.Load(data))
                        {
                            var result = new byte[symmetricKeyData.Key.Length];
                            Array.Copy(symmetricKeyData.Key, result, symmetricKeyData.Key.Length);
                            return result;
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                if (ctx.CreatingNewKey)
                {
                    var token = tokenList.FirstOrDefault(x => x.Capability.IsInitialized && x.Capability.IsObjectAPISupported && !x.Capability.IsObjectAPIIsReadOnly);
                    if (token != null)
                    {
                        using (var symmetricKeyData = SymmetricKeyData.Generate())
                        {
                            var dataObject = token.CreateObjectAsync(label, symmetricKeyData.RawData.Length, isPrivate: true).Result;
                            dataObject.SetDataAsync(symmetricKeyData.RawData).Wait();

                            var result = new byte[symmetricKeyData.Key.Length];
                            Array.Copy(symmetricKeyData.Key, result, symmetricKeyData.Key.Length);
                            return result;
                        }
                    }
                }

                MessageBox.Show("No matching token was found. Please connect another token."
                    , "Token Engine Key Provider"
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Information);
            }
            catch(Exception e)
            {
                MessageBox.Show($"Failed to create/read key: {e.Message}"
                    , "Token Engine Key Provider"
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Error);
            }

            return null;
        }
    }
}
