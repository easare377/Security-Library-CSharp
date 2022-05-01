using System.Security.Cryptography;
using System.Text;

namespace SecurityUtil
{
    /// <summary>
    /// Provides cryptographic operations or functions.
    /// </summary>
    public class Encryption
    {
        #region "Variable Declaration"
        private const string SaltConst = @"*\\|rRyxfo2hEHP?pjfZx.)&%$"; //"p0987654321p"
        private const string HashAlgorithmConst = "MD5";
        //private const int PasswordIterationsConst = 2;
        private const string InitVectorConst = "@1B2c3D4e5F6g7H8";
        private const int KeySizeConst = 256;
        #endregion

        public enum EncryptionSpeed
        {
            Fastest,
            Medium,
            Slowest,
        }
        public static string AES256EncryptString(string plainText, string password,EncryptionSpeed encryptionSpeed)
        {
            int iterations;
            switch (encryptionSpeed)
            {
                case EncryptionSpeed.Fastest:
                    iterations = 1000;
                    break;
                case EncryptionSpeed.Medium:
                    iterations = 10000;
                    break;
                case EncryptionSpeed.Slowest:
                    iterations = 100000;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(encryptionSpeed), encryptionSpeed, null);
            }
            try
            {
                byte[] initVectorBytes = Encoding.ASCII.GetBytes(InitVectorConst);
                byte[] saltValueBytes = Encoding.ASCII.GetBytes(SaltConst);
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                //Rfc2898DeriveBytes
                var passBytes = new Rfc2898DeriveBytes(password, saltValueBytes, iterations);
                //var passBytes = new PasswordDeriveBytes(password, saltValueBytes, HashAlgorithmConst, passwordIterations);
                byte[] keyBytes = passBytes.GetBytes(KeySizeConst / 8);
                // Create uninitialized Rijndael encryption object.
                var symmetricKey = new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
                // Generate encryptor from the existing key bytes and initialization 
                // vector. Key size will be defined based on the number of the key 
                // bytes.
                byte[] cipherTextBytes;
                using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes))
                {
                    // Define memory stream which will be used to hold encrypted data.
                    using (var memoryStream = new MemoryStream())
                    {
                        // Define cryptographic stream (always use Write mode for encryption).
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            // Start encrypting.
                            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                            // Finish encrypting.
                            cryptoStream.FlushFinalBlock();
                            // Convert our encrypted data from a memory stream into a byte array.
                            cipherTextBytes = memoryStream.ToArray();
                        }
                    }
                }
                // Convert encrypted data into a base64-encoded string.
                string cipherText = Convert.ToBase64String(cipherTextBytes);
                return cipherText;
            }
            catch
            {
                return null;
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="password"></param>
        /// <param name="encryptionSpeed"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static string AES256DecryptString(string cipherText, string password,EncryptionSpeed encryptionSpeed)
        {
            int iterations;
            switch (encryptionSpeed)
            {
                case EncryptionSpeed.Fastest:
                    iterations = 1000;
                    break;
                case EncryptionSpeed.Medium:
                    iterations = 10000;
                    break;
                case EncryptionSpeed.Slowest:
                    iterations = 100000;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(encryptionSpeed), encryptionSpeed, null);
            }
            try
            {
                // Convert strings defining encryption key characteristics into byte
                // arrays. Let us assume that strings only contain ASCII codes.
                // If strings include Unicode characters, use Unicode, UTF7, or UTF8
                // encoding.
                byte[] initVectorBytes = Encoding.UTF8.GetBytes(InitVectorConst);
                byte[] saltValueBytes = Encoding.UTF8.GetBytes(SaltConst);
                // Convert our ciphertext into a byte array.
                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
                // First, we must create a password, from which the key will be 
                // derived. This password will be generated from the specified 
                // passphrase and salt value. The password will be created using
                // the specified hash algorithm. Password creation can be done in
                // several iterations.
                var passBytes = new Rfc2898DeriveBytes(password, saltValueBytes, iterations);
                //PasswordDeriveBytes passBytes = new PasswordDeriveBytes(password, saltValueBytes, HashAlgorithmConst, PasswordIterationsConst);
                // Use the password to generate pseudo-random bytes for the encryption
                // key. Specify the size of the key in bytes (instead of bits).
                byte[] keyBytes = passBytes.GetBytes(KeySizeConst / 8);
                // Create uninitialized Rijndael encryption object.
                // It is reasonable to set encryption mode to Cipher Block Chaining (CBC).
                var symmetricKey = new RijndaelManaged {Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7};
                //Use default options for other symmetric key parameters.
                // Generate decryptor from the existing key bytes and initialization 
                // vector. Key size will be defined based on the number of the key 
                // bytes.
                byte[] plainTextBytes;
                int decryptedByteCount;
                using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes))
                {
                    // Define memory stream which will be used to hold encrypted data.
                    using (var memoryStream = new MemoryStream(cipherTextBytes))
                    {
                        // Define memory stream which will be used to hold encrypted data.
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            // Since at this point we don't know what the size of decrypted data
                            // will be, allocate the buffer long enough to hold ciphertext;
                            // plaintext is never longer than ciphertext.
                            plainTextBytes = new byte[cipherTextBytes.Length + 1];
                            // Start decrypting.
                            int readBufferSize = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                            decryptedByteCount = readBufferSize;
                            while (readBufferSize > 0)
                            {
                                readBufferSize = cryptoStream.Read(plainTextBytes,  decryptedByteCount, plainTextBytes.Length - decryptedByteCount);
                                decryptedByteCount += readBufferSize;
                            }
                            // decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                            // int rem = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                            // rem.ToString();
                        }
                    }
                }
                // Convert decrypted data into a string. 
                // Let us assume that the original plaintext string was UTF8-encoded.
                string plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                // Return decrypted string.
                return plainText;
            }
            catch
            {
                return null;
            }
        }
    }
}
