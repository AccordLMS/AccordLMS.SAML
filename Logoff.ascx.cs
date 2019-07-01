using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;


using System.IO;
using System.Threading;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Modules;
using DotNetNuke.Security;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Exceptions;
using DotNetNuke.Services.Localization;
using DotNetNuke.Services.Log.EventLog;
using DotNetNuke.Entities.Users;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Collections.Specialized;

namespace DNN.Authentication.SAML
{
    public partial class Logoff : AuthenticationLogoffBase
    {
        private static DNNAuthenticationSAMLAuthenticationConfig config;
        private readonly IEventLogController eventLog = new EventLogController();
        public void LogToEventLog(string methodName, string message)
        {
            eventLog.AddLog("DNN.Authentication.SAML." + methodName + " : " + DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss:fff"), message, PortalSettings, -1, EventLogController.EventLogType.ADMIN_ALERT);
        }


        protected override void OnLoad(EventArgs e)
        {
            //LogToEventLog("Logoff.OnLoad()", "enter");
            base.OnLoad(e);
            try
            {
                //LogToEventLog("DNN.Authentication.SAML.Logoff.OnLoad(post)", string.Format("(Request.HttpMethod: {0}, Session[sessionIndexFromSAMLResponse]: {1}", Request.HttpMethod, Session["sessionIndexFromSAMLResponse"]));

                //config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);
                //UserInfo user = UserController.GetCurrentUserInfo();
                //LogToEventLog("Logoff.OnLoad()", string.Format("Logging off from saml {0}", user == null ? "null" : user.Username));
                //X509Certificate2 cert = StaticHelper.GetCert(config.OurCertFriendlyName);


                //XmlDocument request = GenerateSAMLLogoffRequest(user.Username);
                //request = StaticHelper.SignSAMLRequest2(request, cert);
                //string convertedRequestXML = StaticHelper.Base64CompressUrlEncode(request.OuterXml);
                //string convertedSigAlg = HttpUtility.UrlEncode("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                //byte[] signature = StaticHelper.SignString2(string.Format("SAMLRequest={0}&RelayState={1}&SigAlg={2}", convertedRequestXML, "NA", convertedSigAlg), cert);
                //string convertedSignature = HttpUtility.UrlEncode(Convert.ToBase64String(signature)); 
                //string redirectTo = config.IdPLogoutURL +
                //    "?SAMLRequest=" + convertedRequestXML +
                //    "&RelayState=NA" + 
                //    "&SigAlg=" + convertedSigAlg +
                //    "&Signature=" + convertedSignature
                //;
                config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);
                base.OnLogOff(e);
                Session.Remove("sessionIndexFromSAMLResponse");

                //LogToEventLog("Logoff()", string.Format("Redirecting to {0}", redirectTo));
                Response.Redirect(config.IdPLogoutURL);
            }
            catch (System.Threading.ThreadAbortException tae)
            {
                LogToEventLog("DNN.Authentication.SAML.Logoff.OnLoad(tae)", "ThreadAbortException");
                //Response.Redirect(Page.ResolveUrl(redirectTo), false);
            }
            catch (Exception ex)
            {
                LogToEventLog("DNN.Authentication.SAML.Logoff.OnLoad()", string.Format("Exception  {0}", ex.Message));
            }

        }

        

        private XmlDocument GenerateSAMLLogoffRequest(string userName)
        {
            DateTime now = DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Utc);
            string authnRequestID = "_" + Guid.NewGuid().ToString().Replace("-", "");

            string requestXML = @"<samlp:LogoutRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" " +
                @" ID=""" + authnRequestID + @"""" +
                @" Version=""2.0"" " +
                @" IssueInstant=""" + now.ToString("O") + @"""" +
                @" Reason=""urn:oasis:names:tc:SAML:2.0:logout:user""" +
                @" Destination=""" + config.IdPLogoutURL + @""" >" +
                @" <saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">" + config.OurIssuerEntityID + @"</saml:Issuer>" +
                @" <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">" + userName + @"</saml:NameID>" +
                @" <samlp:SessionIndex>" + Session["sessionIndexFromSAMLResponse"] + "</samlp:SessionIndex>" +
                @" </samlp:LogoutRequest>
          ";

            XmlDocument xml = new XmlDocument();
            //xml.PreserveWhitespace = false;
            xml.LoadXml(requestXML);
            return xml;
        }

    }
}  
   