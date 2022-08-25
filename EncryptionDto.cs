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
        
        public string assymetricEncryptedMessage { get; set; }
        public string assymetricDecryptedMessage { get; set; }
        public string symmetricEncryptedMessage { get; set; }
        public string symmetricDecryptedMessage { get; set; }
    }
}
