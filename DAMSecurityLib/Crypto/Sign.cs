using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using Org.BouncyCastle.Pkcs;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Text;
using iText.Kernel.Geom;
using iText.Forms.Fields.Properties;
using iText.Forms.Form.Element;

namespace DAMSecurityLib.Crypto
{
    /// <summary>
    /// Provides functionality for signing documents using digital signatures.
    /// </summary>
    public class Sign
    {
        #region Private Attributes

        private X509Certificate2? certificate;
        private Certificates.CertificateInfo? certificateInfo;
        private Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder().Build();
        private string storeAlias = "";

        #endregion

        /// <summary>
        /// Initializes the class's certificate attributes with a certificate from disk.
        /// </summary>
        /// <param name="pfxFileName">Certificate file disk path.</param>
        /// <param name="pfxPassword">Certificate password.</param>
        public void InitCertificate(string pfxFileName, string pfxPassword)
        {
            // Initialize the certificate and certificateInfo attributes
            certificate = new X509Certificate2(pfxFileName, pfxPassword);

            // Initialize the pkcs12Store and storeAlias attributes
            pkcs12Store.Load(new FileStream(pfxFileName, FileMode.Open, FileAccess.Read), pfxPassword.ToCharArray());
            
            // Get the first key entry from the pkcs12Store
            foreach (string currentAlias in pkcs12Store.Aliases)
            {
                if (pkcs12Store.IsKeyEntry(currentAlias))
                {
                    storeAlias = currentAlias;
                    break;
                }
            }
            // Initialize the certificateInfo attribute
            certificateInfo = Certificates.CertificateInfo.FromCertificate(pfxFileName, pfxPassword);
        }

        /// <summary>
        /// Signs a PDF document and saves the result to disk.
        /// This method embeds a digital signature inside the PDF document.
        /// </summary>
        /// <param name="inputFileName">Input PDF file path to sign.</param>
        /// <param name="outputFileName">Output PDF file path to save the result file.</param>
        /// <param name="showSignature">Indicates whether the signature is visible in the PDF document.</param>
        public void SignPdf(string inputFileName, string outputFileName, bool showSignature)
        {
            FileStream fs = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            SignPdf(fs, outputFileName, showSignature);
        }

        /// <summary>
        /// Signs a PDF document and saves the result to disk memory stream.
        /// This method embeds a digital signature inside the PDF document.
        /// </summary>
        /// <param name="inputPdfStream">Input PDF stream to sign.</param>
        /// <param name="outputFileName">Output PDF file path to save the result.</param>
        /// <param name="showSignature">Indicates whether the signature is visible in the PDF document.</param>
        public void SignPdf(Stream inputPdfStream, string outputFileName, bool showSignature)
        {
            AsymmetricKeyParameter key = pkcs12Store.GetKey(storeAlias).Key;

            X509CertificateEntry[] chainEntries = pkcs12Store.GetCertificateChain(storeAlias);
            IX509Certificate[] chain = new IX509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = new X509CertificateBC(chainEntries[i].Certificate);
            PrivateKeySignature signature = new PrivateKeySignature(new PrivateKeyBC(key), "SHA256");

            using (PdfReader pdfReader = new PdfReader(inputPdfStream))
            using (FileStream result = File.Create(outputFileName))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                if (showSignature)
                {
                    CreateSignatureAppearanceField(pdfSigner);
                }

                pdfSigner.SignDetached(signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
            }
        }

        /// <summary>
        /// Signs a filedisk file with the global class certificate.
        /// </summary>
        /// <param name="inputFileName">Filedisk input file path to sign.</param>
        /// <param name="outputFileName">Filedisk output file path to save the result.</param>
        public void SignFile(string inputFileName, string outputFileName)
        {
            if (certificate != null)
            {
                byte[] inputBytes = File.ReadAllBytes(inputFileName);
                byte[] outputBytes = SignDocument(certificate, inputBytes);

                File.WriteAllBytes(outputFileName, outputBytes);
            }
        }

        /// <summary>
        /// Returns the SHA-256 HASH from an input byte array.
        /// </summary>
        /// <param name="input">Input byte array to obtain SHA-256 HASH.</param>
        /// <returns>SHA-256 HASH.</returns>
        public string SHA256Hash(byte[] input)
        {
            using (SHA256 sHA256 = SHA256.Create())
            {
                byte[] hashBytes = sHA256.ComputeHash(input);
                StringBuilder builder = new StringBuilder();

                foreach (byte b in hashBytes)
                {
                    builder.Append(b.ToString("x2"));
                }

                return builder.ToString();
            }
        }

        /// <summary>
        /// Signs a byte array document with the certificate.
        /// </summary>
        /// <param name="certificate">Certificate used to sign the document.</param>
        /// <param name="document">Document byte array to sign.</param>
        /// <returns>Byte array with the signed document.</returns>
        internal static byte[] SignDocument(X509Certificate2 certificate, byte[] document)
        {
            ContentInfo contentInfo = new ContentInfo(document);
            SignedCms signedCms = new SignedCms(contentInfo, false);
            CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
            signedCms.ComputeSignature(signer);

            return signedCms.Encode();
        }

        /// <summary>
        /// Adds a signature field rectangle inside a PDF document.
        /// </summary>
        /// <param name="pdfSigner">PdfSigner used to sign the document.</param>
        internal void CreateSignatureAppearanceField(PdfSigner pdfSigner)
        {
            var pdfDocument = pdfSigner.GetDocument();
            var pageRect = pdfDocument.GetPage(1).GetPageSize();
            var size = new PageSize(pageRect);
            pdfDocument.AddNewPage(size);
            var totalPages = pdfDocument.GetNumberOfPages();
            float yPos = pdfDocument.GetPage(totalPages).GetPageSize().GetHeight() - 100;
            float xPos = 0;
            Rectangle rect = new Rectangle(xPos, yPos, 200, 100);

            pdfSigner.SetFieldName("signature");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.GetFieldName())
                .SetContent(new SignedAppearanceText()
                    .SetSignedBy(certificateInfo?.Organization)
                    .SetReasonLine("" + " - " + "")
                    .SetLocationLine("Location: " + certificateInfo?.Locality)
                    .SetSignDate(pdfSigner.GetSignDate()));

            pdfSigner.SetPageNumber(totalPages).SetPageRect(rect)
                .SetSignatureAppearance(appearance);
        }
    }
}
