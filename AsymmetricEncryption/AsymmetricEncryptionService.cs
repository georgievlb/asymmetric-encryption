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
        /// <param name="usePrivateKey">Specify whether to use the private key or not.</param>
        /// <param name="keySizeInBits">Key size in bits. Default is 2048.</param>
        public RSAParameters RetrieveKeyPair(string containerName, bool useMachineKeyStore, bool usePrivateKey, int keySizeInBits = 2048)
        {
            string containerLocation = useMachineKeyStore == true                      // For more information on container location check out this article: Understanding Machine-Level and User-Level RSA Key Containers: https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiOioqv-4HqAhWOXsAKHVT2ACAQFjAAegQIBBAB&url=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fprevious-versions%2Faspnet%2Ff5cs0acs(v%253Dvs.100)&usg=AOvVaw2oYIcE-G4ifzP-GR6HO-Co
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
        /// <param name="rsaParameters">The parameters for the RSACryptoServiceProvider. The object contains either the public/private key pair or just the public key.</param>
        /// <param name="useOAEPPadding">Specify whether to use Optimal asymmetric encryption padding or not.</param>
        /// <param name="keySize">The key size in bits. The default is 2048.</param>
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

        /// <summary>
        /// Decrypts string data.
        /// </summary>
        /// <param name="encryptedData">Encrypted data in base64 encoding.</param>
        /// <param name="rsaParameters">The parameters for the RSACryptoServiceProvider. The object contains either the public/private key pair or just the public key.</param>
        /// <param name="useOAEPPadding">Specify whether to use Optimal asymmetric encryption padding or not.</param>
        /// <param name="keySize">The key size in bits. The default is 2048.</param>
        /// <returns>Decrypted string in plain text.</returns>
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
