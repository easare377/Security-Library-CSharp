using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using SecurityUtil;

namespace Konect.Security
{
    /// <summary>
    /// Provides functions used to generate or protect passwords or access keys.
    /// </summary>
    public static class PasswordSecurity
    {
        /// <summary>
        /// Indicates if the access key and data provided by the client is valid.
        /// </summary>
        /// <param name="value">The data to verify if its valid.</param>
        /// <param name="securityKey">The secret key that is used to validate the client provided data.</param>
        /// <param name="clientAccessKey">The authentication key that is provided by the client.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <returns></returns>
        public static bool AuthenticateAccessKey(object value, string securityKey, string clientAccessKey)
        {
            if(value == null)
                throw new ArgumentNullException(nameof(value));
            if(securityKey == null)
                throw new ArgumentNullException(nameof(securityKey));
            if(securityKey == "")
                throw new ArgumentException("Invalid security key.",nameof(securityKey));
            if(clientAccessKey == null)
                throw new ArgumentNullException(nameof(clientAccessKey));
            if (clientAccessKey == "")
                throw new ArgumentException("Invalid client access key.", nameof(clientAccessKey));
            string json = JsonConvert.SerializeObject(value);
            string sig = json + securityKey;
            sig = Hashing.GenerateHashKey(sig, Hashing.HashType.Sha256);
            return sig == clientAccessKey;
        }

        /// <summary>
        /// Generates access key derived from the data provided.
        /// </summary>
        /// <param name="value">The object/data to derive the access key from.</param>
        /// <param name="securityKey">The key or password used to generate the access key.</param>
        /// <returns></returns>
        public static string GetAccessKeySig(object value, string securityKey)
        {
            string json = JsonConvert.SerializeObject(value);
            string sig = json + securityKey;
            sig = Hashing.GenerateHashKey(sig, Hashing.HashType.Sha256);
            return sig;
        }

        /// <summary>
        /// Generates a random password using the cryptographic random number generator(<see cref="RNGCryptoServiceProvider"/>).
        /// </summary>
        /// <param name="length">The length of the password bytes. NB:This does not represent the final size of the generated password string.</param>
        /// <returns></returns>
        public static string GenerateRandomPassword(int length)
        {
            //const string lowerCaseConst = "abcdefghijklmnopqursuvwxyz";
            //const string upperCaseConst = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            //const string numbersConst = "0123456789";
            //const string specialsConst = @"`~!@#$%^&*()_+{}[]\'|:;,.></?\";
            //string charSet = $"{lowerCaseConst}{numbersConst}{specialsConst}{upperCaseConst}";
            return GenerateSaltString(length);
        }

        private static RNGCryptoServiceProvider _rngCrypto;

        /// <summary>
        /// Generates a random salt string using the cryptographic random number generator(<see cref="RNGCryptoServiceProvider"/>).
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string GenerateSaltString(int length)
        {
            return Convert.ToBase64String(GenerateSalt(length));
        }

        /// <summary>
        /// Generates a random salt value using the cryptographic random number generator(<see cref="RNGCryptoServiceProvider"/>).
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] GenerateSalt(int length)
        {
            //const int saltLengthConst = 20;
            if (_rngCrypto == null)
                _rngCrypto = new RNGCryptoServiceProvider();
            var salt = new byte[length];
            _rngCrypto.GetNonZeroBytes(salt);
            return salt;
        }

        /// <summary>
        /// Generate a Password-Based Key Derivation Function 2 Hash.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="base64Salt">The key salt used to derive the key. The salt must be a base64String.</param>
        /// <param name="iterations">Indicates the number of iteration used to derive the key.</param>
        /// <returns>Hashed password</returns>
        public static string Generate_PBKDF2_Hash(string password, string base64Salt, int iterations)
        {
            byte[] saltBytes = Convert.FromBase64String(base64Salt);
            return Generate_PBKDF2_Hash(password, saltBytes,iterations);
        }

        /// <summary>
        /// Generate a Password-Based Key Derivation Function 2 Hash.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="saltBytes">The key salt used to derive the key..</param>
        /// <param name="iterations">Indicates the number of iteration used to derive the key.</param>
        /// <returns>Hashed password</returns>
        public static string Generate_PBKDF2_Hash(string password, byte[] saltBytes,int iterations)
        {
            //const int iterationsConst = 10000;
            var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes,iterations);
            return Convert.ToBase64String(pbkdf2.GetBytes(32));
        }

        #region Auth Key
        /// <summary>
        /// Creates an authentication token for secure user verification.
        /// </summary>
        /// <param name="clientKey">The password or key used to generate the token.</param>
        /// <param name="authData">The content of the authentication token.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <returns></returns>
        public static string GenerateAuthKey(string clientKey, object authData)
        {
            if (clientKey == null)
                throw new ArgumentNullException(nameof(clientKey));
            if (clientKey == "")
                throw new ArgumentException("Invalid authentication client key", nameof(clientKey));
            if (authData == null)
                throw new ArgumentNullException(nameof(authData));
            //convert auth data object to json text.
            string json = JsonConvert.SerializeObject(authData);
            //encrypt json text.
            clientKey = Encryption.AES256EncryptString(json, clientKey, Encryption.EncryptionSpeed.Fastest);
            char[] chs = clientKey.ToArray();
            //replace cypher text character with other characters to prevent brute force attacks.
            for (int i = 0; i < clientKey.Length; i++)
            {
                chs[i] = chs[i] switch
                {
                    'a' => 'o',
                    'e' => 'u',
                    'i' => 'a',
                    'o' => 'i',
                    'u' => 'e',
                    'A' => 'E',
                    'E' => 'I',
                    'I' => 'A',
                    'O' => 'U',
                    'U' => 'O',
                    _ => chs[i]
                };
            }
            return new string(chs);
        }

        /// <summary>
        /// Verifies if the authentication key is valid.
        /// </summary>
        /// <param name="authToken">The authentication key to validate.</param>
        /// <param name="clientKey">The password key used to used to encrypt the authentication token.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool IsValidAuthKey(string authToken, string clientKey)
        {
            //object authData = null;
            return IsValidAuthKey(authToken, clientKey, out object _);
        }

        /// <summary>
        /// Verifies if the authentication key is valid.
        /// </summary>
        /// <param name="authToken">The authentication key to validate.</param>
        /// <param name="clientKey">The password key used to used to encrypt the authentication token.</param>
        /// <param name="authData">The content of the authentication token.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool IsValidAuthKey<T>(string authToken, string clientKey, out T authData)
        {
            authData = default(T);
            //check for valid parameters.
            if (authToken == null)
                throw new ArgumentNullException(nameof(authToken));
            if (authToken == "")
                throw new ArgumentException("Invalid authentication token.", nameof(authToken));
            if (clientKey == null)
                throw new ArgumentNullException(nameof(clientKey));
            if (clientKey == "")
                throw new ArgumentException("Invalid authentication client key.", nameof(clientKey));
            char[] chs = authToken.ToArray();
            //replace modified characters with their correct values.
            for (int i = 0; i < authToken.Length; i++)
            {
                chs[i] = chs[i] switch
                {
                    'a' => 'i',
                    'e' => 'u',
                    'i' => 'o',
                    'o' => 'a',
                    'u' => 'e',
                    'A' => 'I',
                    'E' => 'A',
                    'I' => 'E',
                    'O' => 'U',
                    'U' => 'O',
                    _ => chs[i]
                };
            }
            authToken = new string(chs);
            try
            {
                string content = Encryption.AES256DecryptString(authToken, clientKey, Encryption.EncryptionSpeed.Fastest);
                if (content == null)
                    return false;
                authData = JsonConvert.DeserializeObject<T>(content);
            }
            catch(Exception e)
            {
                Console.WriteLine(JsonConvert.SerializeObject(e));
                return false;
            }
            return true;
        }

        #endregion
    }
}
