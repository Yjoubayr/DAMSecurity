using DAMSecurityLib.Certificates;
using DAMSecurityLib.Crypto;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace iTestCertificat
{
    /// <summary>
    /// Collection of tests for DAMSecurityLib.Certificates and DAMSecurityLib.Crypto functionalities.
    /// </summary>
    public class Tests
    {
        string TestCertificateFileName, TestCertificatePassword;

        [SetUp]
        public void Setup()
        {
            // Set up the paths and password for the test certificate
            TestCertificateFileName = AppDomain.CurrentDomain.BaseDirectory + "\\certificat.pfx";
            TestCertificatePassword = "1234";
        }

        [Test]
        public void GeneratePfx_GeneratesCertificateFile()
        {
            // Arrange
            CertificateInfo info = new CertificateInfo();
            info.CommonName = "Yossef";

            // Act
            Autosigned.GeneratePfx(TestCertificateFileName, TestCertificatePassword, info);

            // Assert
            var info2 = CertificateInfo.FromCertificate(TestCertificateFileName, TestCertificatePassword);
            Assert.AreEqual(info.CommonName, info2.CommonName);
        }

        [Test]
        public void GeneratePfx_WithDefaultInfo_GeneratesCertificateFile()
        {
            // Act
            Autosigned.GeneratePfx(TestCertificateFileName, TestCertificatePassword);

            // Assert
            Assert.IsTrue(File.Exists(TestCertificateFileName));
        }

        [Test]
        public void PublicKeyInfo_ReturnsValidBase64String()
        {
            // Arrange 
            Autosigned.GeneratePfx(TestCertificateFileName, TestCertificatePassword);

            // Act
            string publicKeyInfo = Autosigned.PublicKeyInfo(TestCertificateFileName, TestCertificatePassword);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(publicKeyInfo));
        }

        [Test]
        public void CreateNew_GeneratesCertificate()
        {
            // Arrange
            CertificateInfo info = new CertificateInfo();

            // Act 
            X509Certificate2 certificate = Autosigned.CreateNew(info);

            // Assert
            Assert.IsNotNull(certificate);
        }

        // Testing CertificateInfo
        [Test]
        public void DistinguishedName_FormsCorrectly()
        {
            // Arrange
            var certificateInfo = new CertificateInfo
            {
                CommonName = "TestCert",
                Organization = "TestOrg",
                Locality = "TestLocality",
                State = "TestState",
                Country = "TestCountry",
                Email = "test@example.com",
                Address = "TestAddress",
                PostalCode = "TestPostalCode",
            };

            // Act
            var distinguishedName = certificateInfo.DistinguishedName;

            // Assert
            Assert.AreEqual("CN=TestCert,O=TestOrg, L=TestLocality, ST=TestState, C=TestCountry, Email=test@example.com, StreetAddress=TestAddress, PostalCode=TestPostalCode", distinguishedName);
        }

        [Test]
        public void GetCertificateField_ReturnsCorrectValue()
        {
            // Arrange
            var subject = "CN=TestCert,O=TestOrg, L=TestLocality, ST=TestState, C=TestCountry, Email=test@example.com, StreetAddress=TestAddress, PostalCode=TestPostalCode";
            var fieldIdentifier = "O=";

            // Act
            var fieldValue = CertificateInfo.GetCertificateField(subject, fieldIdentifier);

            // Assert
            Assert.AreEqual("TestOrg", fieldValue);
        }

        [Test]
        public void SHA256Hash_ReturnsSameHashForSameInput()
        {
            // Arrange
            var signInstance = new Sign();
            string text = "Hello, World!";
            byte[] input1 = Encoding.UTF8.GetBytes(text);

            // Act
            string hash1 = signInstance.SHA256Hash(input1);

            // Assert
            Assert.AreEqual(hash1, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", "Hashes should be equal for the same input.");
        }

        [TearDown]
        public void Teardown()
        {
            // Clean up: Delete the test certificate file after each test
            if (File.Exists(TestCertificateFileName))
            {
                File.Delete(TestCertificateFileName);
            }
        }
    }
}
