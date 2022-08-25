using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace httpsTest001.Controllers
{
    

    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        private static string _privateKey;
        private static string _publicKey;
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

        public static string decryptString(string data)
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

        public static string EncryptString(string data)
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

        [HttpGet]
        public EncryptionDto Get()
        {
            var rsa = new RSACryptoServiceProvider(2048);
            _privateKey = rsa.ToXmlString(true);
            _publicKey = rsa.ToXmlString(false);
            var plainMessage = "This is the message.";
            var encryptedMessage = EncryptString(plainMessage);
            return new EncryptionDto
            {
                plainMessage = plainMessage,
                hashedMessage = sha256_hash(plainMessage),
                encryptedMessage = encryptedMessage,
                decryptedMessage = decryptString(encryptedMessage)
            };
        }
    }
}
