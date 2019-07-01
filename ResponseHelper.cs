using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;

namespace DNN.Authentication.SAML
{

    public static class StaticHelper
    {
        public static X509Certificate2 GetCert(string friendlyName)
        {
            //http://stackoverflow.com/questions/23394654/signing-a-xml-document-with-x509-certificate
            string s = string.Empty;

            X509Certificate2 myCert = new X509Certificate2("", "");
            //var store = new X509Store(StoreLocation.LocalMachine);
            //store.Open(OpenFlags.ReadOnly);
            //var certificates = store.Certificates;
            ////LogToEventLog("DNN.Authentication.SAML.FindCert()", string.Format("Found {0} certs", certificates.Count));
            //foreach (var certificate in certificates)
            //{
            //    s += string.Format("cert subj : {0}, friendly name : {1}; ", certificate.Subject, certificate.FriendlyName);
            //    if (certificate.FriendlyName.ToLower().Contains(friendlyName.ToLower()))
            //    {
            //        myCert = certificate;
            //    }
            //}

            ////LogToEventLog("DNN.Authentication.SAML.FindCert()", string.Format("certs info : {0}", s));
            //if (myCert == null)
            //    throw new Exception("x509 Certificate with " + friendlyName + " in its friendly name was not found");

            return myCert;
        }

        public static XmlDocument SignSAMLRequest(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            XmlElement xmlDigitalSignature = CreateXMLSignature(xmlDoc, myCert);
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
            return xmlDoc;
        }

        public static XmlDocument SignSAMLRequest2(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            XmlElement xmlDigitalSignature = CreateXMLSignature(xmlDoc, myCert);
            
            xmlDoc.DocumentElement.InsertAfter(xmlDoc.ImportNode(xmlDigitalSignature, true), xmlDoc.DocumentElement.FirstChild);
            return xmlDoc;
        }

        public static XmlElement CreateXMLSignature(XmlDocument xmlDoc, X509Certificate2 myCert)
        {
            //https://msdn.microsoft.com/en-us/library/ms229745(v=vs.110).aspx

            RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)myCert.PrivateKey;
            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = rsaKey;
            Reference reference = new Reference();
            reference.Uri = "";
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            signedXml.AddReference(reference);
            //add KeyInfo clause -  https://msdn.microsoft.com/en-us/library/ms148731(v=vs.110).aspx ---------
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(myCert));
            signedXml.KeyInfo = keyInfo;
            //--------------------------------------------------------------------------------------------------
            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            return xmlDigitalSignature;
        }

        public static byte[] SignString(string text, X509Certificate2 myCert)
        {
            //http://blogs.msdn.com/b/alejacma/archive/2008/06/25/how-to-sign-and-verify-the-signature-with-net-and-a-certificate-c.aspx

            // Hash the data
            SHA1Managed sha1 = new SHA1Managed();
            UnicodeEncoding encoding = new UnicodeEncoding();
            //UTF8Encoding encoding = new UTF8Encoding();
            byte[] data = encoding.GetBytes(text);
            byte[] hash = sha1.ComputeHash(data);

            // Sign the hash
            RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider)myCert.PrivateKey;
            byte[] signedBytes = rsaKey.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            return signedBytes;
        }

        public static byte[] SignString3(string text, X509Certificate2 cert)
        {
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(cert.PrivateKey.ToXmlString(true));
            UnicodeEncoding encoding = new UnicodeEncoding();
            byte[] data = encoding.GetBytes(text);

            //Sign the data
            byte[] sig = key.SignData(data, CryptoConfig.MapNameToOID("SHA1"));
            return sig;
        }

        public static byte[] SignString2(string text, X509Certificate2 cert)
        {
            //http://stackoverflow.com/questions/3240222/get-private-key-from-bouncycastle-x509-certificate-c-sharp
            AsymmetricKeyParameter bouncyCastlePrivateKey = TransformRSAPrivateKey(cert.PrivateKey);

            //http://stackoverflow.com/questions/8830510/c-sharp-sign-data-with-rsa-using-bouncycastle
            ISigner sig = SignerUtilities.GetSigner("SHA1withRSA");
            sig.Init(true, bouncyCastlePrivateKey);
            var data = Encoding.UTF8.GetBytes(text);
            sig.BlockUpdate(data, 0, data.Length);
            return sig.GenerateSignature();
        }

        public static AsymmetricKeyParameter TransformRSAPrivateKey(AsymmetricAlgorithm privateKey)
        {
            RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }



        internal static string Base64UrlEncode(string xml)
        {
            return HttpUtility.UrlEncode(Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)));
        }

        public static string Base64CompressUrlEncode(string xml)
        {
            //http://stackoverflow.com/questions/12090403/how-do-i-correctly-prepare-an-http-redirect-binding-saml-request-using-c-sharp
            string base64 = string.Empty;
            var bytes = Encoding.UTF8.GetBytes(xml);
            using (var output = new MemoryStream())
            {
                using (var zip = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionMode.Compress))
                {
                    zip.Write(bytes, 0, bytes.Length);
                }
                base64 = Convert.ToBase64String(output.ToArray());
            }
            return HttpUtility.UrlEncode(base64);
        }

        public static string Base64CompressUrlEncode(XmlDocument doc)
        {
            string xml = doc.OuterXml;
            return Base64CompressUrlEncode(xml);
        }

        public static byte[] StringToByteArray(string st)
        {
            return Convert.FromBase64String(st);
        }

        public static string ByteArrayToString(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }

    public class ResponseHandler
    {
        protected XmlDocument xmlDocResponse;
        protected X509Certificate2 myCert;
        protected X509Certificate2 theirCert;


        public ResponseHandler(string rawResponse, X509Certificate2 myCert, string theirCertString) : this(rawResponse, myCert)
        {
            this.theirCert = new X509Certificate2();
            theirCert.Import(StaticHelper.StringToByteArray(theirCertString));
        }

        public ResponseHandler (string rawResponse, X509Certificate2 myCert, X509Certificate2 theirCert) : this (rawResponse, myCert)
        {
            this.theirCert = theirCert;
        }
        private ResponseHandler(string rawResponse, X509Certificate2 myCert)
        {
            this.myCert = myCert;
      
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            this.xmlDocResponse = new XmlDocument();
            this.xmlDocResponse.PreserveWhitespace = true;
            this.xmlDocResponse.XmlResolver = null;
            this.xmlDocResponse.LoadXml(rawResponse);

            if (DoesNeedToBeDecrypted())
            {
                //Login.LogToEventLog("ResponseHandler(encrypted)","ResponseHandler(encrypted) : enter");

                //get cipher key
                var decodedCipherKey = GetCipherKey(xmlDocResponse, myCert);
                //Login.LogToEventLog("ResponseHandler(encrypted)","ResponseHandler(encrypted) : cipherKey : " + decodedCipherKey);

                //get encrypted data
                XmlNode node = GetNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue");
                if (node == null)
                    throw new Exception("CipherValue node not found");

                string cipherValue = node.InnerText;
                //LogToEventLog("ResponseHandler(encrypted)","GetNameID(encrypted) : ciphervalue {0}", cipherValue);

                EncryptionHelper encryptionHelper = new EncryptionHelper(decodedCipherKey);
                string decryptedValue = encryptionHelper.AesDecrypt(cipherValue);
                Login.LogToEventLog("ResponseHandler(encrypted)", "Response : " + xmlDocResponse.OuterXml);
                Login.LogToEventLog("ResponseHandler(encrypted)","decryptedValue : " + decryptedValue);

                //add decrypted assertion node to the document
                XmlDocumentFragment xfrag = xmlDocResponse.CreateDocumentFragment();
                xfrag.InnerXml = decryptedValue;
                xmlDocResponse.DocumentElement.AppendChild(xfrag);

            }
        }


        public bool IsStatusSuccess()
        {
            XmlNode node = GetNode("/samlp:Response/samlp:Status/samlp:StatusCode");
            if (node == null || node.Attributes["Value"] == null)
                return false;
            else
                return node.Attributes["Value"].Value.EndsWith("Success");
        }

        private bool DoesNeedToBeDecrypted()
        {
            XmlNode nodeEncryptedAssertion = GetNode("/samlp:Response/saml:EncryptedAssertion");
            XmlNode nodeAssertion = GetNode("/samlp:Response/saml:Assertion");

            return nodeAssertion == null && nodeEncryptedAssertion != null;
        }


        public virtual string GetNameID()
        {
            string nameID = string.Empty;

            XmlNode node = GetNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID");
            if (node != null)
                nameID = node.InnerText;


            if (nameID == string.Empty)
                throw new Exception("NameID is not found in the response");
            return nameID;
        }


        public virtual string GetSessionIndex()
        {
            string sessionIndex = string.Empty;

            XmlNode node = GetNode("/samlp:Response/saml:Assertion/saml:AuthnStatement");
            if (node != null && node.Attributes["SessionIndex"] != null)
                sessionIndex = node.Attributes["SessionIndex"].Value; 

            if (sessionIndex == string.Empty)
                throw new Exception("SessionIndex is not found in the response");
            return sessionIndex;
        }





        private byte[] GetCipherKey(XmlDocument xmlDocResponse, X509Certificate2 myCert)
        {
            XmlNode encryptedCipherValueNode = GetNode("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue");
            if (encryptedCipherValueNode == null)
                throw new Exception("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue node is not found");
            string encryptedCipher = encryptedCipherValueNode.InnerText;

            byte[] bytesEncryptedCipher = Convert.FromBase64String(encryptedCipher);
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)myCert.PrivateKey;

            byte[] bytesDecryptedCipher = csp.Decrypt(bytesEncryptedCipher, true);

            return bytesDecryptedCipher;
        }

        private XmlNode GetNode(string path)
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDocResponse.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            manager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#");

            XmlNode node = xmlDocResponse.SelectSingleNode(path, manager);
            return node;
        }

        public string ResponseString()
        {
            return xmlDocResponse == null ? "document == null" : xmlDocResponse.OuterXml;
        }

    }


    public class EncryptionHelper
    {
        //http://stackoverflow.com/questions/17511279/c-sharp-aes-decryption

        private byte[] keyAndIvBytes;

        public EncryptionHelper(byte[] key)
        {
            keyAndIvBytes = key;
        }

        public string ByteArrayToHexString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public string AesDecrypt(string cipherText)
        {
            Byte[] outputBytes = Convert.FromBase64String(cipherText);
            string plaintext = string.Empty;

            using (MemoryStream memoryStream = new MemoryStream(outputBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm().CreateDecryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            plaintext = SanitizeXmlString(plaintext);
            //return plaintext;
            //i am having issues with padding somewhere : (
            plaintext = plaintext.Substring(plaintext.IndexOf("<saml:Assertion"));
            plaintext = plaintext.Substring(0, plaintext.IndexOf("</saml:Assertion>") + "</saml:Assertion>".Length);
            return plaintext;
        }

        //--------------  https://seattlesoftware.wordpress.com/2008/09/11/hexadecimal-value-0-is-an-invalid-character/
        /// <summary>
        /// Remove illegal XML characters from a string.
        /// </summary>
        private string SanitizeXmlString(string xml)
        {
            if (xml == null)
            {
                throw new ArgumentNullException("xml");
            }

            StringBuilder buffer = new StringBuilder(xml.Length);

            foreach (char c in xml)
            {
                if (IsLegalXmlChar(c))
                {
                    buffer.Append(c);
                }
            }

            return buffer.ToString();
        }

        /// <summary>
        /// Whether a given character is allowed by XML 1.0.
        /// </summary>
        private bool IsLegalXmlChar(int character)
        {
            return
            (
                 character == 0x9 /* == '\t' == 9   */          ||
                 character == 0xA /* == '\n' == 10  */          ||
                 character == 0xD /* == '\r' == 13  */          ||
                (character >= 0x20 && character <= 0xD7FF) ||
                (character >= 0xE000 && character <= 0xFFFD) ||
                (character >= 0x10000 && character <= 0x10FFFF)
            );
        }
        //--------------

        private RijndaelManaged GetCryptoAlgorithm()
        {
            RijndaelManaged algorithm = new RijndaelManaged();
            //set the mode, padding and block size
            algorithm.Padding = PaddingMode.None;
            algorithm.Mode = CipherMode.CBC;
            algorithm.KeySize = 128;
            algorithm.BlockSize = 128;
            return algorithm;
        }
    }

}