using System;

namespace AsymmetricEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            AsymmetricEncryptionService asymmetricEncryptionService = new AsymmetricEncryptionService();
            string containerName = "MyKeyStore";
            bool useMachineKeyStore = false;
            bool useOAEPPadding = false;
            var usePrivateKey = false;
            var rsaParams = asymmetricEncryptionService.RetrieveKeyPair(containerName, useMachineKeyStore, usePrivateKey);

            string secret = "My Secret Message 123123123";
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
    }
}
