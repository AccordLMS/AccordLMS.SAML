<%@ Control Language="C#" AutoEventWireup="false" Inherits="DNN.Authentication.SAML.Settings, DNN.Authentication.SAML" CodeBehind="Settings.ascx.cs" %>

<%@ Register TagPrefix="dnn" Namespace="DotNetNuke.UI.WebControls" Assembly="DotNetNuke" %>


<style type="text/css">
	.samlLabel{
		display: inline-block;
		text-align: right;
		float: left;
        position: relative;
        width: 32.075%;
        padding-right: 20px;
        margin-right: 18px;
        overflow: visible;
        text-align: right;
        font-weight: 700;
	}
	.samlTextbox{
		display: inline-block;
		text-align: left;
		float: right;
        margin-right: 100px;
	}

    .samlHeading { clear: both; margin-left: 15px;}
    .samlParagraph { margin-left: 15px; margin-right: 15px;}
</style>

<h3 class="samlHeading">SAML Configuration</h3>
<div class="dnnFormItem">
    <asp:label class="samlLabel" id="lblEnabled" runat="server" Text="Enabled:"></asp:label>
    <asp:CheckBox class="samlTextbox" Checked="true" runat="server" ID="chkEnabled"></asp:CheckBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblIdpUrl" runat="server" Text="IDP URL:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtIdpUrl"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblIdpLogoutUrl" runat="server" Text="IDP Logout URL:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtIdpLogoutUrl"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblConsumerServUrl" runat="server" Text="Service Consumer URL:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtConsumerServUrl"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblOurIssuerEntityId" runat="server" Text="Our Entity ID:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtOurIssuerEntityId"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblDNNAuthName" runat="server" Text="DNN Auth Name:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtDNNAuthName"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblTheirCert" runat="server" Text="X509 Certificate:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtTheirCert" Columns="40" Rows="3" TextMode="MultiLine"></asp:TextBox>
</div>
<h3 class="samlHeading">User Profile Mappings</h3>
<p class="samlParagraph">To map incoming values to their respective DNN Profile values provide the attribute name that should be used to lookup the value in the incoming SAML assertion.</p>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblFirstName" runat="server" Text="First Name:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtFirstName"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblLastName" runat="server" Text="Last Name:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtLastName"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblDisplayName" runat="server" Text="Display Name:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtDisplayName"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label class="samlLabel" ID="lblEmail" runat="server" Text="Email:" />
    <asp:TextBox class="samlTextbox" runat="server" ID="txtEmail"></asp:TextBox>
</div>
<asp:Repeater ID="repeaterProps" runat="server">
    <ItemTemplate>
        <div class="dnnFormItem">
            <asp:Label class="samlLabel" ID="lblProperty" runat="server" Text='<%#Eval("Property") %>' />
            <asp:TextBox class="samlTextbox" runat="server" ID="txtMappedValue" Text='<%#Eval("Mapping") %>'></asp:TextBox>
        </div>
    </ItemTemplate>
</asp:Repeater>

<h3 class="samlHeading">DNN Role Mappings</h3>
<p class="samlParagraph">
    Using this feature you may provide an incoming SAML attribute that will contain a comma separated listing of DNN Roles that should be added to the user.  
    Additionally you may optionally specify a listing of roles that MUST come as part of the SAML Assertion, if they are not found the role would be removed.
</p>

<p class="samlParagraph">Example: If you set "Required Roles" listing to be member,paidmember and a user comes across with only member, they would be added to the member role, and the paidmember
    role if already existing on their account would be removed.  Any additional roles would be added, if the role exists within DNN.
</p>
<div class="dnnFormItem">
    <asp:Label runat="server" class="samlLabel" id="lblRoleAttributeName" text="Role Listing Attribute" />
    <asp:TextBox runat="server" id="txtRoleAttributeName" class="samlTextbox"></asp:TextBox>
</div>
<div class="dnnFormItem">
    <asp:Label runat="server"  class="samlLabel" id="lblRequiredRoles" text="Required Roles" />
    <asp:TextBox runat="server" id="txtRequiredRolesTextbox" class="samlTextbox"></asp:TextBox>
</div>



