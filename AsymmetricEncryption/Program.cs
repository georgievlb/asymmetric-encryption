using System;
using System.Security.Cryptography;

namespace AsymmetricEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            AsymmetricEncryptionService asymmetricEncryptionService = new AsymmetricEncryptionService();
            string containerName = "MyKeyStore";
            bool useMachineKeyStore = true;
            bool useOAEPPadding = false;
            bool usePrivateKey = false;

            try
            {
                var rsaParams = asymmetricEncryptionService.RetrieveKeyPair(containerName, useMachineKeyStore, usePrivateKey);

                string secret = "My Secret Message";
                Console.WriteLine($"Message to encrypt{secret}");

                // Encrypt with public key
                string encryptedSecret = asymmetricEncryptionService.Encrypt(secret, rsaParams, useOAEPPadding);
                Console.WriteLine($"Encrypted string: {encryptedSecret}");

                // Decrypt with private key
                usePrivateKey = true;
                rsaParams = asymmetricEncryptionService.RetrieveKeyPair(containerName, useMachineKeyStore, usePrivateKey);
                string decryptedSecret = asymmetricEncryptionService.Decrypt(encryptedSecret, rsaParams, useOAEPPadding);
                Console.WriteLine($"Decrypted message: {decryptedSecret}");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine(ex.Message);
            }

        }
    }
}
