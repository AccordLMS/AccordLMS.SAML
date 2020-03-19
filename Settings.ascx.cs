#region Usings

using System;

using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Exceptions;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Profile;
using System.Data;
using System.Collections.Generic;
using System.Web.UI.WebControls;

#endregion

namespace DNN.Authentication.SAML
{
    public partial class Settings : AuthenticationSettingsBase
    {
        private const string usrPREFIX = "usr" + "_";

        public override void UpdateSettings()
        {
            try
            {
                DNNAuthenticationSAMLAuthenticationConfig config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);              
                config.PortalID = PortalId;

                config.ConsumerServURL = txtConsumerServUrl.Text;
                config.DNNAuthName = txtDNNAuthName.Text;
                config.Enabled = chkEnabled.Checked;
                config.IdPLogoutURL = txtIdpLogoutUrl.Text;
                config.IdPURL = txtIdpUrl.Text;
                config.OurIssuerEntityID = txtOurIssuerEntityId.Text;
                config.TheirCert = txtTheirCert.Text;
                config.usrDisplayName = txtDisplayName.Text;
                config.usrEmail = txtEmail.Text;
                config.usrFirstName = txtFirstName.Text;
                config.usrLastName = txtLastName.Text;

                DNNAuthenticationSAMLAuthenticationConfig.UpdateConfig(config);

                //Iterate through repeater
                foreach (RepeaterItem item in repeaterProps.Items)
                {
                    if (item.ItemType == ListItemType.Item || item.ItemType == ListItemType.AlternatingItem)
                    {
                        Label lblProperty = (Label)item.FindControl("lblProperty");
                        TextBox txtMapped = (TextBox)item.FindControl("txtMappedValue");
                        PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + lblProperty.Text, txtMapped.Text);
                    }
                }

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
                BindRepeater();
                txtIdpUrl.Text = config.IdPURL;
                txtIdpLogoutUrl.Text = config.IdPLogoutURL;
                txtConsumerServUrl.Text = config.ConsumerServURL;
                txtDisplayName.Text = config.usrDisplayName;
                txtEmail.Text = config.usrEmail;
                txtFirstName.Text = config.usrFirstName;
                txtDNNAuthName.Text = config.DNNAuthName;
                txtLastName.Text = config.usrLastName;
                txtOurIssuerEntityId.Text = config.OurIssuerEntityID;
                txtTheirCert.Text = config.TheirCert;
                chkEnabled.Checked = config.Enabled;


            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }

        private void BindRepeater()
        {
            DataSet ds = new DataSet();
            DataTable dt = ds.Tables.Add("Properties");
            dt.Columns.Add("Property", typeof(string));
            dt.Columns.Add("Mapping", typeof(string));

            Dictionary<string, string> properties = new Dictionary<string, string>();
            ProfilePropertyDefinitionCollection props = ProfileController.GetPropertyDefinitionsByPortal(PortalId);
            foreach (ProfilePropertyDefinition def in props)
            {
                if (def.PropertyName == "FirstName" || def.PropertyName == "LastName")
                {

                }
                else
                {
                    string setting = Null.NullString;
                    DataRow row = ds.Tables[0].NewRow();
                    row[0] = def.PropertyName + ":";
                    if (PortalController.Instance.GetPortalSettings(PortalId).TryGetValue(usrPREFIX + def.PropertyName, out setting))
                    {
                        row[1] = setting;
                    }
                    else
                    {
                        row[1] = "";
                    }
                    ds.Tables[0].Rows.Add(row);
                }
                
            }

            repeaterProps.DataSource = ds;
            repeaterProps.DataBind();

        }
    }


    [Serializable]
    public class DNNAuthenticationSAMLAuthenticationConfig : AuthenticationConfigBase
    {
        private const string PREFIX = "DNN.Authentication.SAML" + "_";
        private const string usrPREFIX = "usr" + "_";
        protected DNNAuthenticationSAMLAuthenticationConfig(int portalID) : base(portalID)
        {
            this.PortalID = portalID;
            Enabled = true;
            string setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "Enabled", out setting))
                Enabled = bool.Parse(setting);

            //setting = Null.NullString;
            //if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "OurCertFriendlyName", out setting))
            //    OurCertFriendlyName = setting;

            //setting = Null.NullString;
            //if (PortalController.GetPortalSettingsDictionary(portalID).TryGetValue(PREFIX + "TheirCert", out setting))
            //    TheirCert = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IdPURL", out setting))
                IdPURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IdPLogoutURL", out setting))
                IdPLogoutURL = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "OurIssuerEntityID", out setting))
                OurIssuerEntityID = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "ConsumerServURL", out setting))
                ConsumerServURL = setting;

            DNNAuthName = "SAML";
            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "DNNAuthName", out setting))
                DNNAuthName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "TheirCert", out setting))
                TheirCert = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "FirstName", out setting))
                usrFirstName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "LastName", out setting))
                usrLastName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "DisplayName", out setting))
                usrDisplayName = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(usrPREFIX + "Email", out setting))
                usrEmail = setting;
        }

        public bool Enabled { get; set; }
        public string IdPURL { get; set; }
        public string IdPLogoutURL { get; set; }
        public string OurIssuerEntityID { get; set; }
        public string ConsumerServURL { get; set; }
        public string DNNAuthName { get; set; }
        public string TheirCert { get; set; }

        public string usrFirstName { get; set; }
        public string usrLastName { get; set; }
        public string usrDisplayName { get; set; }
        public string usrEmail { get; set; }


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
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "TheirCert", config.TheirCert);

            //ClearConfig(config.PortalID);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "FirstName", config.usrFirstName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "LastName", config.usrLastName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "DisplayName", config.usrDisplayName);
            PortalController.UpdatePortalSetting(config.PortalID, usrPREFIX + "Email", config.usrEmail);
        }

        public string getProfilePropertySAMLName(string DNNpropertyName)
        {
            var setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(PortalID).TryGetValue(usrPREFIX + DNNpropertyName, out setting))
            {
                return setting;
            }
            else
            {
                return "";
            }
        }

        
    }
}

