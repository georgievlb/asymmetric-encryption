*Please note that this project works only in a Windows environment*

# Asymmetric Encryption
This project demonstrates how to create and use asymmetric key pairs, store them in the Windows key store and use them to encrypt and decrypt data.

## AsymmetricEncryptionService
This class is implemented according to:

https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netcore-3.1

## Key Container

Upon creation/retreival of the key container, the ```CspProviderFlags``` determines its location.

```CspProviderFlags.UseMachineKeyStore``` will place them in:
*C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys*

If the ```CspProviderFlags``` is not set, the container will be placed in 
C:\Users\{{user}}\AppData\Roaming\Microsoft\Crypto\RSA\{{guid-folder}}\

If the container exists, the key pair that it holds will be used for encryption/decryption. Otherwise, a new container with the same name will be created:

**Note: Creating a key container with the same name will not generate the same key pair.**

Each time a new container is created, the container name as well as the actual file in Windows will have the same names but a new key pair will be generated i.e. the public and private keys will be different:

https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
