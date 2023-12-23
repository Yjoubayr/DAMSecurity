using DAMSecurityLib.Certificates;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using iText.Signatures;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;

namespace DAMSecurityGUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btSelectPdf_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            if (fileDialog.ShowDialog() == true)
            {
                txtPdfFile.Text = fileDialog.FileName;
            }
        }

        private void btSelectPfx_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            if (fileDialog.ShowDialog() == true)
            {
                txtPfxFile.Text = fileDialog.FileName;
            }
        }

        public byte[] CreatePdfMemoria()
        {
            using (var stream = new MemoryStream())
            {
                var writer = new PdfWriter(stream);
                var pdf = new PdfDocument(writer);
                var document = new Document(pdf);
                document.Add(new Paragraph("Titul 1"));

                // Agregar un tablero (Table) con 3 columnas
                float[] columnWidths = { 1, 1, 1 };
                Table table = new Table(columnWidths);

                table.AddCell(new Cell().Add(new Paragraph("Cell 1")));
                table.AddCell(new Cell().Add(new Paragraph("Cell 2")));
                table.AddCell(new Cell().Add(new Paragraph("Cell 3")));

                document.Add(table);

                document.Close();

                return stream.ToArray();
            }
        }

        public void VerifySignatures(string path)
        {
            using (PdfDocument pdfDoc = new PdfDocument(new PdfReader(path)))
            {
                SignatureUtil signUtil = new SignatureUtil(pdfDoc);
                List<string> names = (List<string>)signUtil.GetSignatureNames();

                if(names.Count == 0)
                {
                    MessageBox.Show("No té firma.");
                }
                else
                {
                    foreach (string name in names)
                    {
                        Console.WriteLine("===== " + name + " =====");
                        VerifySignature(signUtil, name);
                    }
                }
            }
        }

        public PdfPKCS7 VerifySignature(SignatureUtil signUtil, string name)
        {
            PdfPKCS7 pkcs7 = signUtil.ReadSignatureData(name);

            MessageBox.Show("Signature covers whole document: " + signUtil.SignatureCoversWholeDocument(name));
            MessageBox.Show("Document revision: " + signUtil.GetRevision(name) + " of " + signUtil.GetTotalRevisions());
            MessageBox.Show("Integrity check OK? " + pkcs7.VerifySignatureIntegrityAndAuthenticity());

            return pkcs7;
        }

        private void EncryptGeneratedPdf(string pdfFilePath, string encryptionPassword)
        {
            try
            {
                DAMSecurityLib.Crypto.AESCrypt aesCrypt = new DAMSecurityLib.Crypto.AESCrypt();
                // Aquí puedes establecer una clave y un IV personalizados si es necesario
                // aesCrypt.Key = ...; 
                // aesCrypt.IV = ...;

                byte[] pdfBytes = File.ReadAllBytes(pdfFilePath);
                byte[] encryptedPdfBytes = aesCrypt.Encrypt(Encoding.UTF8.GetString(pdfBytes));

                // Sobrescribe el archivo PDF original con el PDF encriptado
                File.WriteAllBytes(pdfFilePath, encryptedPdfBytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Couldn't encrypt generated PDF");
                MessageBox.Show(ex.ToString());
            }
        }

        private void btSign_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                DAMSecurityLib.Crypto.Sign sign = new DAMSecurityLib.Crypto.Sign();
                sign.InitCertificate(this.txtPfxFile.Text, this.txtPfxPassword.Text);

                byte[] pdfBytes;
                if (String.IsNullOrEmpty(this.txtPdfFile.Text))
                { 
                    pdfBytes = CreatePdfMemoria();
                }
                else
                {
                    pdfBytes = File.ReadAllBytes(this.txtPdfFile.Text);
                }

                using (MemoryStream pdfStream = new MemoryStream(pdfBytes))
                {
                    sign.SignPdf(pdfStream, this.txtOutFile.Text, this.chkShowSignature.IsChecked == true);
                }

                MessageBox.Show("Signed pdf was generated");

                VerifySignatures(this.txtOutFile.Text);
                
                MessageBox.Show("Verify signatures");

                if (!String.IsNullOrEmpty(txtPasswordEncrypt.Text))
                {
                    // Después de firmar el PDF, encripta el PDF resultant
                    EncryptGeneratedPdf(this.txtOutFile.Text, this.txtPasswordEncrypt.Text);

                    MessageBox.Show("Signed and encrypted pdf was generated");
                }
                
                MessageBox.Show("Finalitzat!");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Couldn't sign pdf file");
                MessageBox.Show(ex.ToString());
            }
        }

        private void btSelectOut_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                txtOutFile.Text = saveFileDialog.FileName;
            }
        }

        private void btSelectPfxCert_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                txtPfxFileCert.Text = saveFileDialog.FileName;
            }
        }

        private void btGenerateCert_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrEmpty(txtCertName.Text))
            {
                MessageBox.Show("Certificate name is mandatory");
                return;
            }
            if (String.IsNullOrEmpty(txtCertOrganization.Text))
            {
                MessageBox.Show("Certificate organization is mandatory");
                return;
            }
            if (String.IsNullOrEmpty(txtCertLocality.Text))
            {
                MessageBox.Show("Certificate locality is mandatory");
                return;
            }

            DAMSecurityLib.Certificates.CertificateInfo certificateInfo = new DAMSecurityLib.Certificates.CertificateInfo();
      
            certificateInfo.CommonName = txtCertName.Text;
            certificateInfo.Organization=txtCertOrganization.Text;
            certificateInfo.Locality=txtCertLocality.Text;

            try
            {
                Autosigned.GeneratePfx(txtPfxFileCert.Text, txtPfxPasswordCert.Text, certificateInfo);
                MessageBox.Show("Certificated generated successefully");
            } catch (Exception ex)
            {
                MessageBox.Show("Couldn't generate certificate");
                MessageBox.Show(ex.ToString());
            }
        }
    }
}
