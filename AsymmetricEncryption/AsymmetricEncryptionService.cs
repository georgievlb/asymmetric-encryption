using System;
using System.Security.Cryptography;
using System.Text;

namespace AsymmetricEncryption
{
    // This service is implemented according to https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netcore-3.1
    public class AsymmetricEncryptionService
    {
        private readonly CspParameters cspParameters;

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
        /// <param name="keySizeInBits">Key size in bits. Default is 2048.</param>
        public RSAParameters RetrieveKeyPair(string containerName, bool useMachineKeyStore, bool usePrivateKey, int keySizeInBits = 2048)
        {
            string containerLocation = useMachineKeyStore == true
                ? "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys"               // Windows 10 key store
                : "C:\\Users\\{LOCAL_USER}\\AppData\\Roaming\\Microsoft\\Crypto\\RSA"; // Local user profile key store. The containers are in a GUID subfolder

            cspParameters.KeyContainerName = containerName;
            if (useMachineKeyStore)
            {
                cspParameters.Flags = CspProviderFlags.UseMachineKeyStore;
            }

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySizeInBits, cspParameters);
            CspKeyContainerInfo info = new CspKeyContainerInfo(cspParameters);

            Console.WriteLine($"Key Container name: {info.KeyContainerName}");
            Console.WriteLine($"Unique Key Container name: {info.UniqueKeyContainerName}");
            Console.WriteLine($"Key Container Location: {containerLocation}");

            if (usePrivateKey == true)
            {
                return rsa.ExportParameters(true);
            }
            else
            {
                return rsa.ExportParameters(false);
            }
        }

        /// <summary>
        /// Encrypts string data.
        /// </summary>
        /// <param name="stringDataToEncrypt">String data to encrypt.</param>
        /// <param name="encryptWithPrivateKey"></param>
        /// <param name="useOAEPPadding">OAEPPadding</param>
        /// <returns>Encrypted string data in base64 encoding.</returns>
        public string Encrypt(string stringDataToEncrypt, RSAParameters rsaParameters, bool useOAEPPadding, int keySize = 2048)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize, cspParameters);
            rsa.ImportParameters(rsaParameters);

            byte[] dataToEncryptBytes = Encoding.UTF8.GetBytes(stringDataToEncrypt);
            byte[] encryptedBytes = rsa.Encrypt(dataToEncryptBytes, useOAEPPadding);
            string encryptedDataInBase64 = Convert.ToBase64String(encryptedBytes);

            return encryptedDataInBase64;
        }

        public string Decrypt(string encryptedData, RSAParameters rsaParameters, bool useOAEPPadding, int keySize = 2048)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize, cspParameters);
            rsa.ImportParameters(rsaParameters);

            byte[] encryptedDataBytes = Convert.FromBase64String(encryptedData);
            byte[] decryptBytes = rsa.Decrypt(encryptedDataBytes, useOAEPPadding);
            string secretMessage = Encoding.Default.GetString(decryptBytes);

            return secretMessage;
        }

    }
}
