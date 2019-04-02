using System;
using System.Security.Cryptography;
using System.Text;

namespace HashFunction
{
    class Program
    {
        // Hash-based Message Authentication Code (HMAC)
        static void Main(string[] args)
        {
            HMAC_RIPEMD160();
        }

        static void HMAC_RIPEMD160()
        {
            var ogirinalMessage = "Hello world";

            // Create a random key using a random number generator. This would be the
            // secret key shared by sender and receiver.
            var secretkey = new byte[64];

            // RNGCryptoServiceProvider is an implementation of a random number generator.
            using (var rng = new RNGCryptoServiceProvider())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(secretkey);
            }

            // Use the secret key to sign the message.
            var signedMessage = SignMessage(secretkey, ogirinalMessage);

            // Verify the signed message
            VerifyMessage(secretkey, ogirinalMessage, signedMessage);

            string SignMessage(byte[] key, string plainMsg)
            {
                // Initialize the keyed hash object.
                using (HMACRIPEMD160 hmac = new HMACRIPEMD160(key))
                {
                    // Compute the hash of the input message.
                    var hashValue = hmac.ComputeHash(Encoding.ASCII.GetBytes(plainMsg));
                    var hashText = Convert.ToBase64String(hashValue);
                    return hashText;
                }
            }
            bool VerifyMessage(byte[] key, string plainMsg, string signedMsg)
            {
                var err = false;

                // Initialize the keyed hash object. 
                using (var hmac = new HMACRIPEMD160(key))
                {
                    var signedOriginData = hmac.ComputeHash(Encoding.ASCII.GetBytes(plainMsg));
                    var signedData = Convert.FromBase64String(signedMsg);
                    for (var i = 0; i < signedOriginData.Length; i++)
                    {
                        if (signedOriginData[i] != signedData[i])
                        {
                            err = true;
                            break;
                        }
                    }
                }

                if (err)
                {
                    Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                }
                else
                {
                    Console.WriteLine("Hash values agree -- no tampering occurred.");
                }

                return !err;
            }
        }
    }
}
