using System;
using System.Security.Cryptography;
using System.Text;

namespace Konect.Security
{
    /// <summary>
    /// Defines methods used to encrypt or compute password hash.
    /// </summary>
    // public class Hashing
    // {
    //     /// <summary>
    //     /// Indicates the algorithm used to compute the hash of an object. 
    //     /// </summary>
    //     public enum HashType
    //     {
    //         Md5 = 0,
    //         Sha1 = 1,
    //         Sha256 = 2
    //     }
    //
    //     /// <summary>
    //     /// Computes the hash value for the specified string value.
    //     /// </summary>
    //     /// <param name="value">The string value to hash.</param>
    //     /// <param name="hashType">The algorithm used to compute the hash value of the provided string value/.</param>
    //     /// <exception cref="ArgumentNullException"></exception>
    //     /// <returns></returns>
    //     public static string GenerateHashKey(string value, HashType hashType)
    //     {
    //         if(value == null)
    //             throw new ArgumentNullException(nameof(value));
    //         dynamic hash;
    //         switch (hashType)
    //         {
    //             case HashType.Md5:
    //                 hash = MD5.Create();
    //                 break;
    //             case HashType.Sha1:
    //                 hash = SHA1.Create();
    //                 break;
    //             case HashType.Sha256:
    //                 hash = SHA256.Create();
    //                 break;
    //             default:
    //                 throw new ArgumentOutOfRangeException(nameof(hashType), hashType, null);
    //         }
    //         using (hash)
    //         {
    //             var hashHex = new StringBuilder();
    //             byte[] hashValue = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
    //             hash.Clear();
    //             for (var i = 0; i <= hashValue.Length - 1; i++)
    //                 hashHex.Append(hashValue[i].ToString("X2"));
    //             return hashHex.ToString();
    //         }
    //     }
    // }
}
