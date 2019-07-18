# DNN.Authentication.SAML
SAML 2.0 Authentication Provider

A free, open source authentication provider for DNN.

You can now Single Sign On from a remote website (if it has implemented SAML) to your DNN Portal.

SAML
https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
Security Assertion Markup Language (SAML) is an open standard for exchanging authentication and authorization data between parties, in particular, between an identity provider and a service provider. SAML is an XML-based markup language for security assertions (statements that service providers use to make access-control decisions). SAML is also:

A set of XML-based protocol messages
A set of protocol message bindings
A set of profiles (utilizing all of the above)
The single most important use case that SAML addresses is web browser single sign-on (SSO). Single sign-on is relatively easy to accomplish within a security domain (using cookies, for example) but extending SSO across security domains is more difficult and resulted in the proliferation of non-interoperable proprietary technologies. The SAML Web Browser SSO profile was specified and standardized to promote interoperability.

https://en.wikipedia.org/wiki/Identity_provider_(SAML)
A SAML identity provider is a system entity that issues authentication assertions in conjunction with a single sign-on (SSO) profile of the Security Assertion Markup Language (SAML).

In the SAML domain model, a SAML authority is any system entity that issues SAML assertions.[OS 1] Two important examples of SAML authorities are the authentication authority and the attribute authority.

Available at GitHub
https://github.com/AccordLMS/AccordLMS.SAML

Current Features
- Single SIgn On to a DNN site from a remot site using a SAML identity provider
- Match your DNN Profile properties and User properties with SAML Claims
- Sync these values during a User login 
- Creates and Syncs a new DNN User during login if it doesn't exist

Wish List
- Create / Sync DNN Roles based on SAML Claims

Please feel free to utilized the provider and let us know if you encounter any problems.  We have used it for several or our LMS clients and it is stable and working without problem.  Contact any of the GitHub contributors for assistance (within reason).  Also, please submit pull requests if you add features.  Our team will review then and then include in the master release.
