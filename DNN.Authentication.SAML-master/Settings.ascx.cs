#region Usings

using System;

using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Exceptions;
using DotNetNuke.UI.WebControls;
using System.ComponentModel;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Instrumentation;

#endregion

namespace DNN.Authentication.SAML
{
    public partial class Settings : AuthenticationSettingsBase
    {
        public override void UpdateSettings()
        {
            try
            {
                var config = (DNNAuthenticationSAMLAuthenticationConfig)SettingsEditor.DataSource;
                config.PortalID = PortalId;
                DNNAuthenticationSAMLAuthenticationConfig.UpdateConfig(config);
            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                DNNAuthenticationSAMLAuthenticationConfig config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);
                SettingsEditor.DataSource = config;
                SettingsEditor.DataBind();
            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }
    }


    [Serializable]
    public class DNNAuthenticationSAMLAuthenticationConfig : AuthenticationConfigBase
    {
        private const string PREFIX = "DNN.Authentication.SAML" + "_";
        protected DNNAuthenticationSAMLAuthenticationConfig(int portalID) : base(portalID)
        {
            this.PortalID = portalID;
            Enabled = true;
            string setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "Enabled", out setting))
                Enabled = bool.Parse(setting);

            //setting = Null.NullString;
            //if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "OurCertFriendlyName", out setting))
            //    OurCertFriendlyName = setting;

            //setting = Null.NullString;
            //if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "TheirCert", out setting))
            //    TheirCert = setting;

            setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "IdPURL", out setting))
                IdPURL = setting;

            setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "IdPLogoutURL", out setting))
                IdPLogoutURL = setting;

            setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "OurIssuerEntityID", out setting))
                OurIssuerEntityID = setting;

            setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "ConsumerServURL", out setting))
                ConsumerServURL = setting;

            DNNAuthName = "SAML";
            setting = Null.NullString;
            if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "DNNAuthName", out setting))
                DNNAuthName = setting;
        }

        public bool Enabled { get; set; }
        //public string OurCertFriendlyName { get; set; }
        //public string TheirCert { get; set; }
        public string IdPURL { get; set; }
        public string IdPLogoutURL { get; set; }
        public string OurIssuerEntityID { get; set; }
        public string ConsumerServURL { get; set; }
        public string DNNAuthName { get; set; }

        //public static void ClearConfig(int portalId)
        //{
        //    string key = PREFIX + portalId;
        //    DataCache.RemoveCache(key);
        //}

        public static DNNAuthenticationSAMLAuthenticationConfig GetConfig(int portalId)
        {
            var config = new DNNAuthenticationSAMLAuthenticationConfig(portalId);
            return config;
        }

        public static void UpdateConfig(DNNAuthenticationSAMLAuthenticationConfig config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "Enabled", config.Enabled.ToString());
            //PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurCertFriendlyName", config.OurCertFriendlyName);
            //PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "TheirCert", config.TheirCert);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPURL", config.IdPURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IdPLogoutURL", config.IdPLogoutURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "OurIssuerEntityID", config.OurIssuerEntityID);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "ConsumerServURL", config.ConsumerServURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "DNNAuthName", config.DNNAuthName);
            //ClearConfig(config.PortalID);
        }
    }
}

