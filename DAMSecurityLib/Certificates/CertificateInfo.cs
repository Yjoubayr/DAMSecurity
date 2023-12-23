using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DAMSecurityLib.Certificates
{
    /// <summary>
    /// This class  establishes the necessary properties to obtain the information of the generated
    /// digital certificates
    /// </summary>
    public class CertificateInfo
    {
        /// <summary>
        /// Certificate CommonName
        /// This property is mandatory and its default value is SelfSignedCert
        /// </summary>
        public string CommonName { get; set; } = "SelfSignedCert";
        
        /// <summary>
        /// Certificate Organization Name
        /// This property is optional
        /// </summary>
        public string Organization { get; set;} = "UserName";
        
        /// <summary>
        /// Certificate Organization Locality
        /// This property is optional
        /// </summary>
        public string? Locality { get; set; } = null;

        /// <summary>
        /// Certificate Organization State
        /// This property is optional
        /// </summary>
        public string? State { get; set;} = null;

        /// <summary>
        /// Certification Organization Country
        /// This property is optional
        /// </summary>
        public string? Country { get; set; } = null;

        /// <summary>
        /// Certification Organization Email
        /// This property is optional
        /// </summary>
        public string? Email { get; set;} = null;

        /// <summary>
        /// Certification Organization Street Address
        /// This property is optional
        /// </summary>
        public string? Address { get;set; } = null;

        /// <summary>
        /// Certification Origanization Postal Code
        /// This property is optional
        /// </summary>
        public string? PostalCode { get; set;} = null;

        /// <summary>
        /// Certification Initial validation DateTimeOffset Period
        /// </summary>
        public DateTimeOffset NotBefore { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Certification final validation DatetimeOffset Period
        /// The certification doesn't work after this time
        /// </summary>
        public DateTimeOffset NotAfter { get; set; } = DateTimeOffset.UtcNow.AddYears(1);

        /// <summary>
        /// Default Certificate DistinguishedName 
        /// This propoerty is created from the others properties
        /// </summary>
        public string DistinguishedName
        {
            get
            {
                string dn = $"CN={CommonName}";

                if (Organization != null)
                    dn += $",O={Organization}";            
                if (Locality != null)
                    dn += $", L={Locality}";
                if (State != null)
                    dn += $", ST={State}";
                if (Country != null)
                    dn += $", C={Country}";
                if (Email!=null)
                    dn += $", Email={Email}";
                if (Address != null)
                    dn += $", StreetAddress={Address}";
                if (PostalCode != null)
                    dn += $", PostalCode={PostalCode}";

                return dn;
            }
        }

        /// <summary>
        /// Returns CertificateInfo of the certificate passes as parametres
        /// </summary>
        /// <param name="certificatePath">Certificate path in disk</param>
        /// <param name="certificatePassword">Certificate password</param>
        /// <returns>CertificateInfo associated to the certificate</returns>
        public static CertificateInfo FromCertificate(string certificatePath, string certificatePassword)
        {
            var certificate = new X509Certificate2(certificatePath, certificatePassword);
            CertificateInfo info = new CertificateInfo();

            info.CommonName = GetCertificateField(certificate.Subject, "CN=");
            info.Organization = GetCertificateField(certificate.Subject, "O=");

            info.Locality = GetCertificateField(certificate.Subject, "L=");
            if (String.IsNullOrEmpty(info.Locality))
                info.Locality = null;
            info.State = GetCertificateField(certificate.Subject, "ST=");
            if (String.IsNullOrEmpty(info.State))
                info.State = null;
            info.Country = GetCertificateField(certificate.Subject, "C=");
            if (String.IsNullOrEmpty(info.Country)) 
                info.Country = null;
            info.Email = GetCertificateField(certificate.Subject, "Email=");
            if (String.IsNullOrEmpty(info.Email)) 
                info.Email = null;
            info.Address = GetCertificateField(certificate.Subject, "StreetAddress=");
            if (String.IsNullOrEmpty(info.Address)) 
                info.Address = null;
            info.PostalCode = GetCertificateField(certificate.Subject, "PostalCode=");
            if (String.IsNullOrEmpty(info.PostalCode))
                info.PostalCode = null;

            return info;
        }

        /// <summary>
        /// Gets certificated field from subject identified by fieldIdentifier
        /// </summary>
        /// <param name="subject">Subject to extract fieldIdentifier</param>
        /// <param name="fieldIdentifier">Identifier field to extract</param>
        /// <returns>Certificate Field</returns>
        public static string GetCertificateField(string subject, string fieldIdentifier)
        {
            int start = subject.IndexOf(fieldIdentifier);
            if (start >= 0)
            {
                start += fieldIdentifier.Length;
                int end = subject.IndexOf(',', start);
                if (end == -1)
                {
                    end = subject.Length;
                }
                return subject.Substring(start, end - start).Trim();
            }
            return string.Empty;
        }
    }
}
