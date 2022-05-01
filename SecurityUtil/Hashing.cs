using System.Security.Cryptography;
using System.Text;

namespace SecurityUtil
{
    /// <summary>
    /// Defines methods used to encrypt or compute password hash.
    /// </summary>
    public class Hashing
    {
        /// <summary>
        /// Indicates the algorithm used to compute the hash of an object. 
        /// </summary>
        public enum HashType
        {
            /// <summary>
            /// Indicates a hash function producing a 128-bit hash value.
            /// </summary>
            Md5 = 0,
            /// <summary>
            /// Indicates a hash function producing a 160-bit hash value.
            /// </summary>
            Sha1 = 1,
            /// <summary>
            /// Indicates a hash function producing a 256-bit hash value.
            /// </summary>
            Sha256 = 2
        }

        /// <summary>
        /// Computes the hash value for the specified string value.
        /// </summary>
        /// <param name="value">The string value to hash.</param>
        /// <param name="hashType">The algorithm used to compute the hash value of the provided string value.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <returns></returns>
        public static string GenerateHashKey(string value, HashType hashType)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            var hashHex = new StringBuilder();
            byte[] hashValue = GenerateHashKey(Encoding.UTF8.GetBytes(value), hashType);
            for (var i = 0; i <= hashValue.Length - 1; i++)
                hashHex.Append(hashValue[i].ToString("X2"));
            return hashHex.ToString();
        }

        /// <summary>
        /// Computes the hash value for the specified data.
        /// </summary>
        /// <param name="data">The byte array to hash</param>
        /// <param name="hashType">The algorithm used to compute the hash value of the provided string value/.</param>
        ///  /// <exception cref="ArgumentNullException"></exception>
        /// <returns></returns>
        public static byte[] GenerateHashKey(byte[] data, HashType hashType)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            dynamic hash;
            switch (hashType)
            {
                case HashType.Md5:
                    hash = MD5.Create();
                    break;
                case HashType.Sha1:
                    hash = SHA1.Create();
                    break;
                case HashType.Sha256:
                    hash = SHA256.Create();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashType), hashType, null);
            }
            using (hash)
            {
                byte[] hashValue = hash.ComputeHash(data);
                hash.Clear();
                return hashValue;
            }
        }
    }
}
