using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace httpsTest001.Controllers
{
    

    [Route("[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        private static string _privateKey;
        private static string _publicKey;
        private static string _hash = "SHA1";
        private static string _salt = "jeos2m6h1jfo0e8a"; //in a read scenario should be random
        private static string _vector = "k1jf9jepqmnz8hde"; // random as well.
        private static UnicodeEncoding _encoder = new UnicodeEncoding();

        public static String sha256_hash(String value)
        {
            StringBuilder Sb = new StringBuilder();

            using (SHA256 hash = SHA256Managed.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(value));

                foreach (Byte b in result)
                    Sb.Append(b.ToString("x2"));
            }

            return Sb.ToString();
        }

        public static string decryptAsymmetricString(string data)
        {
            var rsa = new RSACryptoServiceProvider();
            var dataArray = data.Split(new char[] { ',' });
            byte[] dataByte = new byte[dataArray.Length];
            for (int i = 0; i < dataArray.Length; i++)
            {
                dataByte[i] = Convert.ToByte(dataArray[i]);
            }

            rsa.FromXmlString(_privateKey);
            var decryptedByte = rsa.Decrypt(dataByte, false);
            return _encoder.GetString(decryptedByte);
        }

        public static string encryptAsymmetricString(string data)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(_publicKey);
            var dataToEncrypt = _encoder.GetBytes(data);
            var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
            var length = encryptedByteArray.Count();
            var item = 0;
            var sb = new StringBuilder();
            foreach (var x in encryptedByteArray)
            {
                item++;
                sb.Append(x);

                if (item < length)
                {
                    sb.Append(',');
                }
            }
            return sb.ToString();
        }
        
        public static string encryptSymmetricString<T>(string data, string password)
            where T: SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Encoding.UTF8.GetBytes(data);

            byte[] encrypted;
            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes =
                    new PasswordDeriveBytes(password, saltBytes, _hash, 2);
                byte[] keyBytes = _passwordBytes.GetBytes(256 / 8);

                cipher.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
                {
                    using (MemoryStream to = new MemoryStream())
                    {
                        using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                        {
                            writer.Write(valueBytes, 0, valueBytes.Length);
                            writer.FlushFinalBlock();
                            encrypted = to.ToArray();
                        }
                    }
                }
                cipher.Clear();
            }
            return Convert.ToBase64String(encrypted);
        }

        public static string decryptSymmetricString<T>(string data, string password)
            where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Convert.FromBase64String(data);

            byte[] decrypted;
            int decryptedByteCount = 0;

            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, 2);
                byte[] keyBytes = _passwordBytes.GetBytes(256 / 8);

                cipher.Mode = CipherMode.CBC;

                try
                {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
                    {
                        using (MemoryStream from = new MemoryStream(valueBytes))
                        {
                            using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                            {
                                decrypted = new byte[valueBytes.Length];
                                decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    return String.Empty;
                }

                cipher.Clear();
            }
            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }

        [HttpGet]
        public EncryptionDto Get()
        {
            var rsa = new RSACryptoServiceProvider(2048);
            
            _privateKey = rsa.ToXmlString(true);
            _publicKey = rsa.ToXmlString(false);
            var plainMessage = "This is the message.";
            var asymmetricEncrypedMessage = encryptAsymmetricString(plainMessage);
            var symmetricEncryptedMessage = encryptSymmetricString<AesManaged>(plainMessage, "myPassword");
            return new EncryptionDto
            {
                plainMessage = plainMessage,
                hashedMessage = sha256_hash(plainMessage),
                assymetricEncryptedMessage = asymmetricEncrypedMessage,
                assymetricDecryptedMessage = decryptAsymmetricString(asymmetricEncrypedMessage),
                symmetricEncryptedMessage = symmetricEncryptedMessage,
                symmetricDecryptedMessage = decryptSymmetricString<AesManaged>(symmetricEncryptedMessage, "myPassword")
            };
        }
    }
}
