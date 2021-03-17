using LoginJwt.Authorization.Models;
using LoginJwt.Tools.Extensions;
using System;
using System.IO;
using System.Security.Cryptography;

namespace LoginJwt.Authorization.Encryptors
{
    public class AesCryptor
    {
        public static AesEncryptModel EncryptStringAes(string plainText, string key, string iv)
        {
            if (plainText.IsAnyNullOrWhiteSpace(key))
            {
                throw new ArgumentException();
            }

            byte[] encrypted;
            var encryptKey = Convert.FromBase64String(key);
            var rgbIv = Convert.FromBase64String(iv);
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = encryptKey;
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, rgbIv);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var result = new AesEncryptModel { Value = Convert.ToBase64String(encrypted) };
            return result;

        }

        public static string DecryptStringAes(string cipherText, string Key, string IV)
        {
            if (cipherText.IsAnyNullOrWhiteSpace(Key, IV))
            {
                throw new ArgumentException();
            }
            string plaintext = null;
            var key = Convert.FromBase64String(Key);
            var iv = Convert.FromBase64String(IV);

            using (var aesAlg = Aes.Create())
            {
                var decryptor = aesAlg.CreateDecryptor(key, iv);

                var cipherTextBytes = Convert.FromBase64String(cipherText);
                using (var msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }
    }
}
