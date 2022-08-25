using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace httpsTest001
{
    public class EncryptionDto
    {
        public string plainMessage { get; set; }
        public string hashedMessage { get; set; }
        public string encryptedMessage { get; set; }
        public string decryptedMessage { get; set; }
    }
}
