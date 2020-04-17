using KeePass.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using TokenEngineForefront.HighApi;

namespace TokenEngineKeyProvider
{
    public sealed class TokenEngineKeyProviderExt : Plugin
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
        private TokenEngine tokenEngine;

        public override bool Initialize(IPluginHost host)
        {
            try
            {
                this.host = host ?? throw new ArgumentNullException("Invalid initialization data.");

                if (tokenEngine == null)
                {
                    var initResult = TokenEngine.CreateTokenEngineAsync().Result;
                    tokenEngine = initResult.Instance;
                }
            }
            catch(Exception e)
            {
                MessageBox.Show($"Failed to initialize plugin:{Environment.NewLine}{Environment.NewLine}{e.Message}"
                    , "Token Engine Key Provider", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            return true;
        }

        public override void Terminate()
        {
            tokenEngine?.Dispose();
            tokenEngine = null;
            host = null;
        }
    }
}
