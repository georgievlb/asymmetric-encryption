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
            int keySize = 2048;
            bool useMachineKeyStore = false;
            bool encryptWithPrivateKey = true;
            bool useOAEPPadding = false;
            asymmetricEncryptionService.RetrieveKeyPair(containerName, useMachineKeyStore, keySize);

            string secret = "My Secret Message 123123123";
            Console.WriteLine($"Message to encrypt{secret}");
            string encryptedSecret = asymmetricEncryptionService.Encrypt(secret, encryptWithPrivateKey, useOAEPPadding);
            Console.WriteLine($"Encrypted string: {encryptedSecret}");

            string decryptedSecret = asymmetricEncryptionService.Decrypt(encryptedSecret, encryptWithPrivateKey, useOAEPPadding);
            Console.WriteLine($"Decrypted message: {decryptedSecret}");
        }
    }
}
