
using DAMSecurityLib.Certificates;
using DAMSecurityLib.Crypto;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using System.Collections.Specialized;

namespace DAMSecurity
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //Autosigned.GeneratePfx("C:\\Users\\dmart126\\Downloads\\tmp\\cert.pfx", "123456");
            CertificateInfo.FromCertificate(@"C:\Users\Moha\source\repos\DAMSecurity\certificat.pfx", "patata123");
            /*string originalFileName = Path.ChangeExtension(Path.GetTempFileName(), "pdf");
            string signedFileName = Path.ChangeExtension(Path.GetTempFileName(), "pdf");

            using (var writer = new PdfWriter(new FileStream( originalFileName, FileMode.Create, FileAccess.Write)))
            {
                using (var pdf = new PdfDocument(writer))
                {
                    Document document = new Document(pdf);
                    document.Add(new Paragraph("Pdf sample "));
                    document.Close();
                }
            }

            Console.WriteLine($"Original pdf file:{originalFileName}");

            new Sign().SignPdf(originalFileName, signedFileName);
            
            Console.WriteLine($"Signed pdf file:{signedFileName}");*/
        }
    }
}