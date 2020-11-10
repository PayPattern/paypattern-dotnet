using System;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            // Generate a new key
            var key = RsaJwk.Generate();
            
            // Or load one from a string
            key = RsaJwk.FromRsaPrivateKey(key.ToRsaPrivateKey());
            
            // The JWK will need to be added to PayPattern.io so we can validate your JWT
            var jwk = key.ToPublicJwk();
            Console.WriteLine($"Public JWK: {jwk}");
            
            // Generate JWTs to authenticate with
            var tokenGenerator = new TokenGenerator(key, "example.com", "api.paypattern.io");
            var jwt = tokenGenerator.Generate("abc");
            Console.WriteLine($"\nJWT: {jwt}");
        }
    }
}