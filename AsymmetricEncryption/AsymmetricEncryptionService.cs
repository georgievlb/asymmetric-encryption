using System;
using System.Security.Cryptography;
using System.Text;

namespace AsymmetricEncryption
{
    // This service is implemented according to https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netcore-3.1
    public class AsymmetricEncryptionService
    {
        private readonly CspParameters cspParameters;
        private RSACryptoServiceProvider rsa;

        public AsymmetricEncryptionService()
        {
            cspParameters = new CspParameters();
        }

        /// <summary>
        /// Generate a key pair and store it within a container.
        /// If the container already exists and holds a key pair, that same key pair will be used.
        /// Otherwise a new key pair will be generated.
        /// Note: Creating a container with the same name will not generate the same key pair.
        /// </summary>
        /// <param name="containerName">The container name.</param>
        /// <param name="useMachineKeyStore">Specify wether or not to use the machine key store.</param>
        /// <param name="keySizeInBits">Key size in bits. Default is 1024.</param>
        public void GenerateKeyPair(string containerName, bool useMachineKeyStore, int keySizeInBits = 1024)
        {
            string containerLocation = useMachineKeyStore == true
                ? "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys"               // Windows 10 key store
                : "C:\\Users\\{LOCAL_USER}\\AppData\\Roaming\\Microsoft\\Crypto\\RSA"; // Local user profile key store. The containers are in a GUID subfolder

            cspParameters.KeyContainerName = containerName;
            if (useMachineKeyStore)
            {
                cspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
            }

            rsa = new RSACryptoServiceProvider(keySizeInBits, cspParameters);
            rsa.PersistKeyInCsp = true;

            CspKeyContainerInfo info = new CspKeyContainerInfo(cspParameters);

            Console.WriteLine($"Key Container name: {info.KeyContainerName}");
            Console.WriteLine($"Unique Key Container name: {info.UniqueKeyContainerName}");
            Console.WriteLine($"Key Container Location: {containerLocation}");
        }

    }
}
