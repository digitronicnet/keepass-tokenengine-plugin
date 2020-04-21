using KeePassLib.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TokenEngineKeyProvider
{
    class SymmetricKeyProvider : KeyProvider
    {
        public const string DataObjectLabel = "keepasskey";

        private IPlugin plugin;

        public SymmetricKeyProvider(IPlugin plugin)
            => this.plugin = plugin ?? throw new ArgumentNullException(nameof(plugin));

        public override string Name => "Token Engine Key Provider";

        public byte[] ProtectedLastProvidedKey { get; private set; }

        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            var title = "Token Engine Key Provider";

            var returnValue = Task.Run(async () =>
            {
                try
                {
                    var tokenList = await plugin.TokenEngine.GetTokenListAsync();

                    foreach (var token in tokenList)
                    {
                        await token.LoadAsync();
                        if (!token.Capability.IsInitialized)
                            continue;

                        var dataObject = (await token.FindObjectsAsync(DataObjectLabel, isPrivate: true))
                            .FirstOrDefault();

                        if (dataObject == null)
                            continue;

                        var data = await dataObject.GetDataAsync();

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

                        if (token == null)
                        {
                            var unitializedToken = tokenList.FirstOrDefault(x => !x.Capability.IsInitialized && x.Capability.CanBeInitialized);
                            if (unitializedToken != null)
                            {
                                if (MessageBox.Show("Uninitialized token found. Do you want to prepare the connected token so that it can be used?"
                                    , title
                                    , MessageBoxButtons.YesNo
                                    , MessageBoxIcon.Question) == DialogResult.Yes)
                                {
                                    await unitializedToken.InitializeExternAsync();
                                    token = unitializedToken;
                                }
                            }
                        }

                        if (token != null)
                        {
                            using (var symmetricKeyData = SymmetricKeyData.Generate())
                            {
                                var dataObject = await token.CreateObjectAsync(DataObjectLabel, symmetricKeyData.RawData.Length, isPrivate: true);
                                await dataObject.SetDataAsync(symmetricKeyData.RawData);

                                var result = new byte[symmetricKeyData.Key.Length];
                                Array.Copy(symmetricKeyData.Key, result, symmetricKeyData.Key.Length);
                                return result;
                            }
                        }
                    }

                    MessageBox.Show("No matching token was found. Please connect another token."
                        , title
                        , MessageBoxButtons.OK
                        , MessageBoxIcon.Information);
                }
                catch (Exception e)
                {
                    MessageBox.Show($"Failed to create/read key: {e.Message}"
                        , title
                        , MessageBoxButtons.OK
                        , MessageBoxIcon.Error);
                }

                return null;
            }).Result;

            if (returnValue != null)
            {
                ProtectedLastProvidedKey = new byte[returnValue.Length];
                Array.Copy(returnValue, ProtectedLastProvidedKey, returnValue.Length);
                ProtectedMemory.Protect(ProtectedLastProvidedKey, MemoryProtectionScope.SameProcess);
            }

            return returnValue;
        }
    }
}
