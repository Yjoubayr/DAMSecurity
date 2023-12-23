using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
//using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Asn1.X509;

namespace DAMSecurityLib.Certificates
{
    /// <summary>
    /// Class to work with autosigned certifictes
    /// </summary>
    public class Autosigned
    {
        /// <summary>
        /// Generate Pfx  Certificate.
        /// This Method generates pfx certificate with default info,
        /// </summary>
        /// <param name="certFileName">Pfx certificate file path</param>
        /// <param name="certPassword">Pfx certificate password</param>
        public static void GeneratePfx(string certFileName, string? certPassword)
        {
            CertificateInfo info = new CertificateInfo();

            GeneratePfx(certFileName, certPassword, info);
        }

        /// <summary>
        /// Generate Pfx certificate.
        /// This method generates pfx certificates with CerticateInfo inside it. 
        /// </summary>
        /// <param name="certFileName">Pfx certificate file path</param>
        /// <param name="certPassword">Pfx certifiate password</param>
        /// <param name="info">Pfx certicicate info to display it</param>
        public static void GeneratePfx(string certFileName, string? certPassword, CertificateInfo info)
        {
            // Create a self-signed certificate 
            X509Certificate2 certificate = CreateNew(info);

            // Save certificate to a file   
            byte[] certBytes = certificate.Export(X509ContentType.Pfx, certPassword);

            // Save cert bytes to a file
            File.WriteAllBytes(certFileName, certBytes);
        }

        /// <summary>
        /// Obtanir public key info string accordint to certificate stored in disx
        /// </summary>
        /// <param name="pfxFileName">Certificate Filsesystem path</param>
        /// <param name="pfxPassword">Certificate password</param>
        /// <returns>string representing public key info</returns>
        public static string PublicKeyInfo(string pfxFileName, string? pfxPassword)
        {
            var certificate = new X509Certificate2(pfxFileName, pfxPassword);
            byte[] publicKeyInfoBytes = certificate.Export(X509ContentType.Cert);
            return Convert.ToBase64String(publicKeyInfoBytes);
        }

        /// <summary>
        /// Geneates certificate witohout saving to disk
        /// </summary>
        /// <param name="info">PFx certiciate info</param>
        /// <returns>certificate object to work with it</returns>
        public static X509Certificate2 CreateNew(CertificateInfo info)
        {
            using (RSA rsa = RSA.Create())
            {
                X500DistinguishedName dn = new X500DistinguishedName(info.DistinguishedName);
                
                // Create a certificate request with the RSA key pair
                CertificateRequest certificateRequest = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Create a self-signed certificate from the request
                X509Certificate2 certificate = certificateRequest.CreateSelfSigned(info.NotBefore, info.NotAfter);
                
                return certificate;
            }
        }   
    }
}
