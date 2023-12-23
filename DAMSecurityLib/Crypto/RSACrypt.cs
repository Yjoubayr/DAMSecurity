using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DAMSecurityLib.Crypto
{
    /// <summary>
    /// Provides functionality for RSA encryption and decryption.
    /// </summary>
    public class RSACrypt
    {
        /// <summary>
        /// Saves the public key of a certificate to a file on disk.
        /// </summary>
        /// <param name="pfxFilename">Pfx file path from which to extract the public key.</param>
        /// <param name="pfxPassword">Password for the Pfx file.</param>
        /// <param name="publicKeyFile">File path to store the certificate's public key.</param>
        public static void SavePublicKey(string pfxFilename, string pfxPassword, string publicKeyFile)
        {
            X509Certificate2 certificate = new X509Certificate2(pfxFilename, pfxPassword);

            RSA? publicKey = certificate.GetRSAPublicKey();
            if (publicKey != null)
            {
                SavePublicKey(publicKey, publicKeyFile);
            }
        }

        /// <summary>
        /// Loads a certificate's public key from a file on disk.
        /// </summary>
        /// <param name="publicKeyFile">File path of the stored public key.</param>
        /// <returns>RSA certificate with the public key.</returns>
        public static RSA LoadPublicKey(string publicKeyFile)
        {
            RSAParameters publicKeyParams = new RSAParameters();
            using (StreamReader reader = new StreamReader(publicKeyFile))
            {
                string? line = reader.ReadLine();
                if (line != null)
                    publicKeyParams.Modulus = Convert.FromBase64String(line);
                line = reader.ReadLine();
                if (line != null)
                    publicKeyParams.Exponent = Convert.FromBase64String(line);
            }

            RSA rsa = RSA.Create();
            rsa.ImportParameters(publicKeyParams);
            return rsa;
        }

        /// <summary>
        /// Saves an RSA public key to a file on disk.
        /// </summary>
        /// <param name="publicKey">RSA public key to be stored on disk.</param>
        /// <param name="publicKeyFile">File path to store the public key.</param>
        public static void SavePublicKey(RSA publicKey, string publicKeyFile)
        {
            RSAParameters publicKeyParams = publicKey.ExportParameters(false);
            using (StreamWriter writer = new StreamWriter(publicKeyFile))
            {
                byte[]? modulus = publicKeyParams.Modulus;
                if (modulus != null)
                    writer.WriteLine(Convert.ToBase64String(modulus));
                byte[]? exponent = publicKeyParams.Exponent;
                if (exponent != null)
                    writer.WriteLine(Convert.ToBase64String(exponent));
            }
        }

        /// <summary>
        /// Encrypts an AES key with an RSA public key.
        /// </summary>
        /// <param name="aesKey">AES Key to be encrypted.</param>
        /// <param name="publicKey">RSA public key to encrypt with.</param>
        /// <returns>Encrypted AES key.</returns>
        public static byte[] EncryptAESKey(byte[] aesKey, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                return encryptedAesKey;
            }
        }

        /// <summary>
        /// Decrypts an AES key with an RSA private key.
        /// </summary>
        /// <param name="encryptedKey">Encrypted AES key to be decrypted.</param>
        /// <param name="certificate">X509Certificate2 containing the private key.</param>
        /// <returns>Decrypted AES key.</returns>
        public static byte[] DecryptAESKeyWithPrivateKey(byte[] encryptedKey, X509Certificate2 certificate)
        {
            using (RSA? rsa = certificate.GetRSAPrivateKey())
            {
                byte[] aesKey;
                if (rsa != null)
                    aesKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
                else
                    aesKey = new byte[0];
                return aesKey;
            }
        }
    }
}
