using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Client
{
    public class RsaJwk
    {
        private readonly RSACryptoServiceProvider _rsa;

        private RsaJwk(RSACryptoServiceProvider rsa)
        {
            _rsa = rsa;
        }
        
        /// <summary>
        /// Generate a new RsaJwk
        /// </summary>
        public static RsaJwk Generate(int keySize = 2048)
        {
            return new RsaJwk(new RSACryptoServiceProvider(2048));
        }

        /// <summary>
        /// Returns a new RsaJwk generated from a B64 encoded private key 
        /// </summary>
        public static RsaJwk FromRsaPrivateKey(string privateKey)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
            return new RsaJwk(rsa);
        }

        /// <summary>
        /// Gets credentials to use when signing a JWT
        /// </summary>
        public SigningCredentials SigningCredentials => 
            new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256Signature);

        /// <summary>
        /// Base64 encoded private key, use this to restore the key later
        /// </summary>
        public string ToRsaPrivateKey()
        {
            return Convert.ToBase64String(_rsa.ExportRSAPrivateKey());
        }
        
        /// <summary>
        /// Base64 public key, could be used to generate a public .pem 
        /// </summary>
        public string ToRsaPublicKey()
        {
            return Convert.ToBase64String(_rsa.ExportRSAPublicKey());
        }

        /// <summary>
        /// Returns a json string of the JWK, pass this to pay pattern
        /// </summary>
        public string ToPublicJwk()
        {
            var rsaParameters = _rsa.ExportParameters(false);
            return JsonConvert.SerializeObject(new
            {
                kty = "RSA",
                use = "sig",
                alg = "RS256",
                n = Base64UrlEncoder.Encode(rsaParameters.Modulus),  // JWK required url b64 encoding
                e = Base64UrlEncoder.Encode(rsaParameters.Exponent),
            });
        }
    }
}