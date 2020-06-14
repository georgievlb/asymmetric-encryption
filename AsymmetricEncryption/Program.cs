using System;

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
            asymmetricEncryptionService.GenerateKeyPair(containerName, useMachineKeyStore, keySize);
        }
    }
}
