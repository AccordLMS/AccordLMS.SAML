#region Usings

using System;
using System.Linq;
using System.Web;
using DotNetNuke.Data;
using DotNetNuke.Entities.Users;        //for UserController
using DotNetNuke.Entities.Profile;
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
using System.Collections.Generic;
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
            if (Request.QueryString["noSAML"] != null)
            {

            }
            else
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
                        string samlCertificate = config.TheirCert;

                        Saml.Response samlResponse = new Saml.Response(samlCertificate);
                        LogToEventLog("Request:", Request.Form["SAMLResponse"].ToString());
                        samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]); //SAML providers usually POST the data into this var
                                                                                      //String xmlExample = "";
                                                                                      //samlResponse.LoadXml(xmlExample);

                        LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("samlResponse is:  ", samlResponse.ToString()));

                        if (samlResponse.IsValid())
                        {
                            LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "saml valid");
                            LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("samlResponse is:  {0}", samlResponse.Xml.ToString()));
                            //WOOHOO!!! user is logged in
                            //YAY!

                            //Some more optional stuff for you
                            //lets extract username/firstname etc
                            string username = "", email = "", firstname = "", lastname = "", displayname = "";
                            try
                            {
                                username = samlResponse.GetNameID();

                                if (username == null)
                                {
                                    LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "USER IS NULL");
                                }
                                else
                                {
                                    if (username == "")
                                    {
                                        LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "USER IS EMPTY");
                                    }

                                }


                                LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Username is: {0} ", username));

                                email = samlResponse.GetUserProperty(config.usrEmail);
                                if (email == null)
                                {
                                    email = samlResponse.GetUserProperty("email");
                                }
                                firstname = samlResponse.GetUserProperty(config.usrFirstName);
                                if (firstname == null)
                                {
                                    firstname = samlResponse.GetUserProperty("firstName");
                                }
                                lastname = samlResponse.GetUserProperty(config.usrLastName);
                                if (lastname == null)
                                {
                                    lastname = samlResponse.GetUserProperty("lastName");
                                }
                                displayname = samlResponse.GetUserProperty(config.usrDisplayName);
                                if (displayname == null)
                                {
                                    displayname = samlResponse.GetUserProperty("displayName");
                                }
                            }
                            catch (Exception ex)
                            {
                                //insert error handling code
                                //no, really, please do
                                LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Exception:......{0}", ex.InnerException.Message));
                            }


                            UserInfo userInfo = UserController.GetUserByName(PortalSettings.PortalId, username);


                            if (userInfo == null)
                            {
                                //user does not exists, it needs to be created.
                                userInfo = new UserInfo();
                                try
                                {
                                    if (username != null && email != null && firstname != null && lastname != null)
                                    {
                                        
                                        
                                        if (displayname == null)
                                        {
                                            userInfo.DisplayName = firstname + " " + lastname;
                                        }
                                        else
                                        {
                                            userInfo.DisplayName = displayname;
                                        }
                                        
                                        userInfo.FirstName = firstname;
                                        userInfo.LastName = lastname;
                                        userInfo.Username = username;
                                        userInfo.Email = email;
                                        userInfo.PortalID = PortalSettings.PortalId;
                                        userInfo.IsSuperUser = false;
                                        userInfo.Membership.Password = UserController.GeneratePassword();

                                        UserCreateStatus usrCreateStatus = new UserCreateStatus();

                                        usrCreateStatus = UserController.CreateUser(ref userInfo);

                                        if (usrCreateStatus == UserCreateStatus.Success)
                                        {
                                            UserInfo usrInfo = UserController.GetUserByName(PortalSettings.PortalId, username);
                                            SetProfileProperties(samlResponse, usrInfo);
                                        }
                                        else
                                        {
                                            LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "Error creating new user..." + usrCreateStatus.ToString());
                                        }
                                    }                                                               
                                }
                                catch (Exception ex)
                                {
                                    LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "Error creating new user...exception:  " + ex.InnerException.Message);
                                }
                                
                            }
                            else
                            {
                                //User already exists

                                //Wen unlock it if necessary
                                if (userInfo.Membership.LockedOut)
                                {
                                    UserController.UnLockUser(userInfo);
                                }
                                LogToEventLog("DNN.Authentication.SAML.OnLoad(post !auth)", String.Format("FoundUser userInfo.Username: {0}", userInfo.Username));


                                try
                                {
                                    //We update the user's info
                                    userInfo.DisplayName = displayname;
                                    userInfo.FirstName = firstname;
                                    userInfo.LastName = lastname;
                                    userInfo.Email = email;

                                    UserController.UpdateUser(PortalSettings.PortalId, userInfo);

                                    //We update the user's properties
                                    SetProfileProperties(samlResponse, userInfo);
                                }
                                catch (Exception ex)
                                {
                                    LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", "Error updating existing user...exception:  " + ex.InnerException.Message);
                                }
                               
                            }


                            //string sessionIndexFromSAMLResponse = responseHandler.GetSessionIndex();
                            //Session["sessionIndexFromSAMLResponse"] = sessionIndexFromSAMLResponse;


                            UserValidStatus validStatus = UserController.ValidateUser(userInfo, PortalId, true);
                            UserLoginStatus loginStatus = validStatus == UserValidStatus.VALID ? UserLoginStatus.LOGIN_SUCCESS : UserLoginStatus.LOGIN_FAILURE;
                            if (loginStatus == UserLoginStatus.LOGIN_SUCCESS)
                            {
                                SetLoginDate(username);                           
                                //Raise UserAuthenticated Event
                                var eventArgs = new UserAuthenticatedEventArgs(userInfo, userInfo.Email, loginStatus, config.DNNAuthName) //"DNN" is default, "SAML" is this one.  How did it get named SAML????
                                {
                                    Authenticated = true,
                                    Message = "User authorized",
                                    RememberMe = false
                                };
                                OnUserAuthenticated(eventArgs);
                            }
                        }
                        else
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
                    LogToEventLog("DNN.Authentication.SAML.OnLoad(tae)", string.Format("Exception is {0}", tae.Message));
                    //Response.Redirect(Page.ResolveUrl(redirectTo), false); 
                }
                catch (Exception ex)
                {
                    LogToEventLog("DNN.Authentication.SAML.OnLoad()", string.Format("Exception  {0}", ex.Message));
                    //redirectTo = "~/";
                }

                //Response.Redirect(Page.ResolveUrl(redirectTo), false);

            }

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

        private void SetLoginDate(string username)
        {
            StringBuilder mysqlstring = new StringBuilder();

            mysqlstring.Append("UPDATE {databaseOwner}aspnet_Membership SET LastLoginDate = @0 where UserId in (select UserId from {databaseOwner}aspnet_Users where UserName = @1)");

            using (DotNetNuke.Data.IDataContext db = DataContext.Instance())
            {
                db.Execute(System.Data.CommandType.Text, mysqlstring.ToString(), DateTime.Now.ToString(), username);
            }
        }

        private void SetProfileProperties(Saml.Response response, UserInfo uInfo)
        {
            try
            {
                Dictionary<string, string> properties = new Dictionary<string, string>();
                ProfilePropertyDefinitionCollection props = ProfileController.GetPropertyDefinitionsByPortal(PortalSettings.PortalId);
                foreach (ProfilePropertyDefinition def in props)
                {
                    string SAMLPropertyName = config.getProfilePropertySAMLName(def.PropertyName);
                    if(SAMLPropertyName != "")
                    {
                        properties.Add(def.PropertyName, response.GetUserProperty(SAMLPropertyName));
                    }                    
                }

                foreach (KeyValuePair<string, string> kvp in properties)
                {
                    uInfo.Profile.SetProfileProperty(kvp.Key, kvp.Value);
                }

                ProfileController.UpdateUserProfile(uInfo);
            }
            catch (Exception exc)
            {
                LogToEventLog("DNN.Authentication.SAML.SetProfileProperties", string.Format("Exception  {0}", exc.Message));
            }

        }
    }
}



