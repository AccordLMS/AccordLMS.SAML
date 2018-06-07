#region Usings

using System;
using System.Linq;
using System.Web;
using DotNetNuke.Entities.Users;        //for UserController
using DotNetNuke.Instrumentation;       //for logger
using DotNetNuke.Services.Log.EventLog; //for eventlog
using DotNetNuke.Services.Authentication;   //for AuthenticationLoginBase
using DotNetNuke.Security.Membership;   //for UserLoginStatus
using System.Security.Claims;           //for ClaimsPrincipal
using System.IdentityModel.Services; //SignInRequestMessage
using System.IdentityModel.Tokens; //SecurityTokenHandlerCollection

using Globals = DotNetNuke.Common.Globals;
using System.Xml;
using System.IO;
using DotNetNuke.Security.Roles;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Saml;


#endregion

namespace DNN.Authentication.SAML
{

	public partial class Login : AuthenticationLoginBase
    {
		private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof (Login));
        private static readonly IEventLogController eventLog = new EventLogController();
        private static DotNetNuke.Entities.Portals.PortalSettings staticPortalSettings;
        private static DNNAuthenticationSAMLAuthenticationConfig config;


        public static void LogToEventLog(string methodName, string message)
        {
            eventLog.AddLog("DNN.Authentication.SAML." + methodName + " : " + DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss:fff"), message, staticPortalSettings, -1, EventLogController.EventLogType.ADMIN_ALERT);
        }

        public override bool Enabled
		{
			get
			{
                return AuthenticationConfig.GetConfig(PortalId).Enabled;
			}
		}

		protected override void OnLoad(EventArgs e)
        {            
            base.OnLoad(e);
            staticPortalSettings = PortalSettings;
            string redirectTo = "~/";
            try
            {

               
                config = DNNAuthenticationSAMLAuthenticationConfig.GetConfig(PortalId);
                if (Request.HttpMethod == "POST" && !Request.IsAuthenticated)
                {
                    //if (Request.HttpMethod == "POST" && !Request.IsAuthenticated)
                    //{
                    //specify the certificate that your SAML provider has given to you
                    string samlCertificate = @"-----BEGIN CERTIFICATE-----
MIIFZzCCBE+gAwIBAgIQB1RolcR/fTpigHg8vUpfezANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQG EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS8w LQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNzdXJhbmNlIFNlcnZlciBDQTAeFw0xNTA5MTcw MDAwMDBaFw0xODExMjkxMjAwMDBaMIGBMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEQ
MA4GA1UEBxMHVG9yb250bzEYMBYGA1UEChMPTG95YWx0eU9uZSwgQ28uMRwwGgYDVQQLExNCdXNp bmVzcyBUZWNobm9sb2d5MRYwFAYDVQQDDA0qLmxveWFsdHkuY29tMIIBIjANBgkqhkiG9w0BAQEF AAOCAQ8AMIIBCgKCAQEAnK+JuOdvOX8NquyyQ8qlrKn4myfmyqRprnS/0MDsW9KYoj/yOPaRVm66 5ARll0uKF61WcrAaA90oKU8M7RB1hvCAevTmPm7QQJrmQ1rn3Pw1BqoX21snvOCOU1K2vJGFn8lJ
xhB8hKaMywQ1GnM0BAHwPj582JjBY4NColzsQLSFSrkZ38BGsazEGzyEIZZe0jc9c/tTZsAODMq2 4FDw+ZO7XFkpTqEiz47C7aPI+u9O58+/0/Qkue8Vr6I4yoDoliF8T1FiQ3G1fqdzUWoIOrg8EUNm nL1511A8+vKWgC0/ZdhZaG/8ZNm18zqS963tu69uBaz3TUmP2Qz2BbpV5QIDAQABo4IB6TCCAeUw HwYDVR0jBBgwFoAUUWj/kK8CB3U8zNllZGKiErhZcjswHQYDVR0OBBYEFAz/hPC/2T5d0UTBKVeU
WbuSsWgcMCUGA1UdEQQeMByCDSoubG95YWx0eS5jb22CC2xveWFsdHkuY29tMA4GA1UdDwEB/wQE AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0fBG4wbDA0oDKgMIYuaHR0 cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItaGEtc2VydmVyLWc0LmNybDA0oDKgMIYuaHR0cDov L2NybDQuZGlnaWNlcnQuY29tL3NoYTItaGEtc2VydmVyLWc0LmNybDBCBgNVHSAEOzA5MDcGCWCG
SAGG/WwBATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGDBggr BgEFBQcBAQR3MHUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBNBggrBgEF BQcwAoZBaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkhpZ2hBc3N1cmFu Y2VTZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAoKZcYHi8LKGh
p2qhuBJMTyVGlAHRiICMe//cNIslxkT1xLa73Ou4McZi2zhzFouxSZw74r5d8Di6Co78Cozvuy9D JusooRPy0P1jdpDvV/UusRrj+p+4el2gQxcZBad4tUFJbBtmglUmFkKUhHyatrurej5bXi37tbze O+QJ607qYCcMHrKm2h2rVXr0x0VbAFy7AsgsDNLLCMgdZ7MJ035VOPL0arKi1vzh/PxyVuJip9nE wDq4y1acR29+A5S0TGFaqMr8pRiKcKA1SCnrQGnJjmuRUhx2dFq1hb10MrNCghKMRR7177HzmWga
m5yVgLzi4Xcefp5i3wrepnBGEA==
-----END CERTIFICATE-----
";

                    Saml.Response samlResponse = new Saml.Response(samlCertificate);
                LogToEventLog("Request:", Request.Form.ToString());
                samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]); //SAML providers usually POST the data into this var
                                                                              //String xmlExample = "";
                                                                              //samlResponse.LoadXml(xmlExample);
                if (samlResponse.IsValid())
                    {
                    LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "saml valid");
                        //WOOHOO!!! user is logged in
                        //YAY!

                        //Some more optional stuff for you
                        //lets extract username/firstname etc
                        string username = "", email, firstname, lastname;
                        try
                        {
                            username = samlResponse.GetNameID();
                        email = samlResponse.GetEmail();
                            firstname = samlResponse.GetFirstName();
                            lastname = samlResponse.GetLastName();
                        }                        
                        catch (Exception ex)
                        {
                            //insert error handling code
                            //no, really, please do
                            LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Redirecting to  {0}", redirectTo));
                        }


                        UserInfo userInfo = UserController.GetUserByName(PortalSettings.PortalId, username);


                        if (userInfo == null)
                        {
                            //User does not exist
                        }
                        else
                        {
                            LogToEventLog("DNN.Authentication.SAML.OnLoad(post !auth)", String.Format("FoundUser userInfo.Username: {0}", userInfo.Username));
                        }


                        //string sessionIndexFromSAMLResponse = responseHandler.GetSessionIndex();
                        //Session["sessionIndexFromSAMLResponse"] = sessionIndexFromSAMLResponse;


                        UserValidStatus validStatus = UserController.ValidateUser(userInfo, PortalId, true);
                        UserLoginStatus loginStatus = validStatus == UserValidStatus.VALID ? UserLoginStatus.LOGIN_SUCCESS : UserLoginStatus.LOGIN_FAILURE;
                        if (loginStatus == UserLoginStatus.LOGIN_SUCCESS)
                        {
                            //Raise UserAuthenticated Event
                            var eventArgs = new UserAuthenticatedEventArgs(userInfo, userInfo.Email, loginStatus, config.DNNAuthName) //"DNN" is default, "SAML" is this one.  How did it get named SAML????
                            {
                                Authenticated = true,
                                Message = "User authorized",
                                RememberMe = false
                            };
                            OnUserAuthenticated(eventArgs);
                        }
                    }else
                    {
                        LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "saml not valid");
                    }
            }
                else if (Request.IsAuthenticated)
            {
                //if (!Response.IsRequestBeingRedirected)
                //    Response.Redirect(Page.ResolveUrl(redirectTo), false);
            }
            else
            {
                XmlDocument request = GenerateSAMLRequest();
                //X509Certificate2 cert = StaticHelper.GetCert(config.OurCertFriendlyName);
                //request = StaticHelper.SignSAMLRequest(request, cert);
                LogToEventLog("DNN.Authentication.SAML.OnLoad()", string.Format("request xml {0}", request.OuterXml));
                String convertedRequestXML = StaticHelper.Base64CompressUrlEncode(request);
                redirectTo = config.IdPURL + (config.IdPURL.Contains("?") ? "&" : "?") + "SAMLRequest=" + convertedRequestXML;
                if (Request.QueryString.Count > 0)
                    redirectTo += "&RelayState=" + HttpUtility.UrlEncode(Request.Url.Query.Replace("?", "&"));

                Response.Redirect(Page.ResolveUrl(redirectTo), false);

            }

        }
            catch (System.Threading.ThreadAbortException tae)
            {
                LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Redirecting to  {0}", redirectTo));
                //Response.Redirect(Page.ResolveUrl(redirectTo), false); 
            }
            catch (Exception ex)
            {
                LogToEventLog("DNN.Authentication.SAML.OnLoad()", string.Format("Exception  {0}", ex.Message));
                //redirectTo = "~/";
            }

            //Response.Redirect(Page.ResolveUrl(redirectTo), false);
        }

        private XmlDocument GenerateSAMLRequest()
        {
            DateTime now = DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Utc);
            string authnRequestID = "_" + Guid.NewGuid().ToString().Replace("-", "");

            string requestXML = @"<samlp:AuthnRequest " +
                @" ID=""" + authnRequestID + @"""" +
                @" IssueInstant = """ + now.ToString("O") + @"""" +
                @" Version = ""2.0"" " +
                @" Destination = """ + config.IdPURL + @"""" +
                @" ForceAuthn = ""false"" " +
                @" IsPassive = ""false"" " +
                @" ProtocolBinding = ""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" " +
                @" AssertionConsumerServiceURL = """ + config.ConsumerServURL + @"""" +
                @" xmlns:samlp = ""urn:oasis:names:tc:SAML:2.0:protocol"">" +
                @" <saml:Issuer xmlns:saml = ""urn:oasis:names:tc:SAML:2.0:assertion"">" + config.OurIssuerEntityID + @"</saml:Issuer>" +
                @" </samlp:AuthnRequest>";

            XmlDocument xml = new XmlDocument();
            xml.LoadXml(requestXML);
            return xml;
        }      

        private void PrintOutKeyValues(string name, System.Collections.Specialized.NameValueCollection coll)
        {
            if (coll == null)
                LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues()", string.Format("{0} is null", name));
            else
            {
                LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues()", string.Format("{0} has {1} elements", name, coll.Count));

                foreach (string key in coll.AllKeys)
                    LogToEventLog("DNN.Authentication.SAML.PrintOutKeyValues(post !auth)", string.Format("{0} [{1}] = [{2}]", name, key, coll[key]));
            }

        }
    }
}



