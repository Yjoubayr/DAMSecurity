using System.Security.Cryptography;

namespace DAMSecurityLib.Crypto
{
    /// <summary>
    /// Provides functionality for AES encryption and decryption.
    /// </summary>
    public class AESCrypt
    {
        #region Private Attributes

        // Aes class used to encrypt/decrypt data
        private Aes aes;

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets or sets the key used for encryption/decryption.
        /// </summary>
        public byte[] Key
        {
            get { return aes.Key; }
            set { aes.Key = value; }
        }

        /// <summary>
        /// Gets or sets the Initialization Vector (IV) used for encryption/decryption.
        /// </summary>
        public byte[] IV
        {
            get { return aes.IV; }
            set { aes.IV = value; }
        }

        #endregion

        /// <summary>
        /// Initializes a new instance of the AESCrypt class with a random key and IV.
        /// </summary>
        public AESCrypt()
        {
            aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
        }

        /// <summary>
        /// Encrypts the provided text and returns the encrypted data.
        /// </summary>
        /// <param name="text">Text to be encrypted.</param>
        /// <returns>Byte array corresponding to the encrypted text.</returns>
        public byte[] Encrypt(string text)
        {
            ICryptoTransform encryptionTransform = aes.CreateEncryptor();
            byte[] encryptedData;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptionTransform, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Writing the plaintext to the CryptoStream
                        streamWriter.Write(text);
                    }
                    encryptedData = memoryStream.ToArray();
                }
            }

            return encryptedData;
        }

        /// <summary>
        /// Decrypts the provided encrypted data and writes it to a file on disk.
        /// </summary>
        /// <param name="encryptedData">Encrypted data to be decrypted.</param>
        /// <param name="outFileName">File path to store the decrypted data.</param>
        public void DecryptToFile(byte[] encryptedData, string outFileName)
        {
            ICryptoTransform decryptionTransform = aes.CreateDecryptor();
            byte[] decryptedData;

            using (MemoryStream memoryStream = new MemoryStream(encryptedData))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptionTransform, CryptoStreamMode.Read))
                {
                    using (MemoryStream decryptedMemoryStream = new MemoryStream())
                    {
                        // Copying the decrypted data from the CryptoStream to the MemoryStream
                        cryptoStream.CopyTo(decryptedMemoryStream);
                        decryptedData = decryptedMemoryStream.ToArray();
                        File.WriteAllBytes(outFileName, decryptedData);
                    }
                }
            }
        }
    }
}
