using KeePass.Plugins;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using TokenEngineForefront.HighApi;

namespace TokenEngineKeyProvider
{
    public sealed class TokenEngineKeyProviderExt : Plugin, IPlugin
    {
        static TokenEngineKeyProviderExt()
        {
            TokenEngineConfigration.ApplicationId = 0x000F;
            TokenEngineConfigration.LibraryPath = @"C:\Windows\System32\LAccessMgmtForefrontLibrary.dll";
            TokenEngineConfigration.ShowPINDialogsIfRequired = true;
            TokenEngineConfigration.ComponentId = 1;
            TokenEngineConfigration.ProductId = 14;
            TokenEngineConfigration.VendorId = 1;
        }

        private IPluginHost host;
        private SymmetricKeyProvider symKeyProvider;
        private ToolStripMenuItem menuItemCopyKey;
        private ToolStripMenuItem menuItemDeleteKey;

        public TokenEngine TokenEngine { get; private set; }

        public override Image SmallIcon { get; } = Resource.token_engine_icon.ToBitmap();

        public override bool Initialize(IPluginHost host)
        {
            try
            {
                this.host = host ?? throw new ArgumentNullException("Invalid initialization data.");

                var initResult = TokenEngine.CreateTokenEngineAsync().Result;
                TokenEngine = initResult.Instance;

                host.KeyProviderPool.Add(symKeyProvider = new SymmetricKeyProvider(this));
            }
            catch(Exception e)
            {
                MessageBox.Show($"Failed to initialize plugin:{Environment.NewLine}{Environment.NewLine}{e.Message}"
                    , "Token Engine Key Provider", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t == PluginMenuType.Main && menuItemCopyKey == null)
            {
                var tokenEngineMenu = new ToolStripMenuItem("Token Engine Plugin", Resource.token_engine_icon.ToBitmap());

                menuItemCopyKey = new ToolStripMenuItem("Copy Key");
                menuItemCopyKey.Click += MenuItemCopyKey_Click;

                menuItemDeleteKey = new ToolStripMenuItem("Clean up all tokens");
                menuItemDeleteKey.Click += MenuItemDeleteKey_Click;

                tokenEngineMenu.DropDownItems.Add(menuItemCopyKey);
                tokenEngineMenu.DropDownItems.Add(menuItemDeleteKey);

                return tokenEngineMenu;
            }

            return base.GetMenuItem(t);
        }

        private void MenuItemDeleteKey_Click(object sender, EventArgs e)
        {
            var title = "Clean up all tokens";

            try
            {
                if (MessageBox.Show("Are you sure you want clean up all connected tokens?"
                    , title
                    , MessageBoxButtons.YesNo
                    , MessageBoxIcon.Question) != DialogResult.Yes)
                    return;


                var tokenList = Task.Run(async () =>
                {
                    var result = await TokenEngine.GetTokenListAsync();
                    foreach (var t in result)
                    {
                        await t.LoadAsync();
                        if (!t.Capability.IsInitialized || !t.Capability.IsObjectAPISupported || t.Capability.IsObjectAPIIsReadOnly)
                            continue;
                    }
                    return result.Where(t => t.Capability.IsInitialized || t.Capability.IsObjectAPISupported || !t.Capability.IsObjectAPIIsReadOnly).ToList();
                }).Result;

                if (tokenList.Count == 0)
                {
                    if (MessageBox.Show("No token was found. Please connect a token."
                        , title
                        , MessageBoxButtons.OK
                        , MessageBoxIcon.Question) != DialogResult.Yes)
                        return;
                }

                var errorMessage = Task.Run(async () =>
                {
                    foreach(var token in tokenList)
                    {
                        try
                        {
                            var objs = await token.FindObjectsAsync(isPrivate: true);
                            await Task.WhenAll(objs.Select(async x => await x.DeleteAsync()));
                        }
                        catch(Exception ex)
                        {
                            return ex.Message;
                        }
                    }                  

                    return string.Empty;
                }).Result;

                if (!string.IsNullOrEmpty(errorMessage))
                    throw new Exception(errorMessage);

                MessageBox.Show($"All connected tokens have been cleaned up."
                    , title
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                var exception = ex;
                if (ex.InnerException != null)
                    exception = ex.InnerException;
                MessageBox.Show($"An error occurred:{Environment.NewLine}{exception.Message}"
                    , title
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Error);
            }
        }

        private void MenuItemCopyKey_Click(object sender, EventArgs e)
        {
            var title = "Copy Last Key";

            try
            {
                var result = MessageBox.Show("Are you sure you want to copy the last key used to the current token?"
                    , title
                    , MessageBoxButtons.YesNo
                    , MessageBoxIcon.Question);

                if (result != DialogResult.Yes)
                    return;

                if (symKeyProvider.ProtectedLastProvidedKey == null)
                    throw new Exception("No key has been used yet. Use a token to log in and try again.");

                var token = Task.Run(async () =>
                {
                    foreach (var t in await TokenEngine.GetTokenListAsync())
                    {
                        await t.LoadAsync();
                        if (!t.Capability.IsInitialized || !t.Capability.IsObjectAPISupported || t.Capability.IsObjectAPIIsReadOnly)
                            continue;

                        return t;
                    }
                    return null;
                }).Result;

                if (token == null)
                    throw new Exception("No suitable token was found.");

                var errorMessage = Task.Run(async () =>
                {
                    var dataObject = (await token.FindObjectsAsync(SymmetricKeyProvider.DataObjectLabel, isPrivate: true))
                                .FirstOrDefault();

                    if (dataObject != null)
                        return "There is already a key on the token.";                    

                    var key = new byte[symKeyProvider.ProtectedLastProvidedKey.Length];

                    try
                    {
                        Array.Copy(symKeyProvider.ProtectedLastProvidedKey, key, symKeyProvider.ProtectedLastProvidedKey.Length);
                        ProtectedMemory.Unprotect(key, MemoryProtectionScope.SameProcess);
                        using (var keyData = new SymmetricKeyData(key))
                        {
                            dataObject = await token.CreateObjectAsync(SymmetricKeyProvider.DataObjectLabel, keyData.RawData.Length, isPrivate: true);
                            await dataObject.SetDataAsync(keyData.RawData);
                        }
                    }
                    catch
                    {
                        try
                        {
                            await dataObject.DeleteAsync();
                        }
                        catch { }

                        throw;
                    }
                    finally
                    {
                        Array.Clear(key, 0, key.Length);
                    }

                    return string.Empty;
                }).Result;

                if (!string.IsNullOrEmpty(errorMessage))
                    throw new Exception(errorMessage);

                MessageBox.Show($"The key was successfully copied to another token."
                    , title
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Information);
            }
            catch(Exception ex)
            {
                var exception = ex;
                if (ex.InnerException != null)
                    exception = ex.InnerException;
                MessageBox.Show($"An error occurred:{Environment.NewLine}{exception.Message}"
                    , title
                    , MessageBoxButtons.OK
                    , MessageBoxIcon.Error);
            }           
        }

        public override void Terminate()
        {
            menuItemCopyKey.Click -= MenuItemCopyKey_Click;
            menuItemDeleteKey.Click -= MenuItemDeleteKey_Click;

            host.KeyProviderPool.Remove(symKeyProvider);
            symKeyProvider = null;

            TokenEngine?.Dispose();
            TokenEngine = null;

            host = null;
        }
    }
}
