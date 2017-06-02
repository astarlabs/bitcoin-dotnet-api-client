using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace AStar.Util
{
    public class JoseUtils
    {
        
        public static string EncodeRS256(string privateKeyString){

            var iat = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            var exp = (Int32)(DateTime.UtcNow.AddMinutes(1).Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            RandomNumberGenerator rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[64];
            rng.GetBytes(bytes);
            
            var hex = FromHex(privateKeyString);

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("exp", exp.ToString()));
            claims.Add(new Claim("iat", iat.ToString()));
            claims.Add(new Claim("jti", new BigInteger(bytes).ToString()));

            var token = CreateToken(claims, hex);

            Console.WriteLine(token);

            return token;

        }

        public static string CreateToken(List<Claim> claims, string privateKey)
            { 

                Console.WriteLine(privateKey);
                string jwt = string.Empty;
                AsymmetricCipherKeyPair key;

                using (StringReader sr = new StringReader(privateKey))
                {
                    PemReader pr = new PemReader(sr);
                    key = (AsymmetricCipherKeyPair)pr.ReadObject();
                }

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)key.Private);

                string json =  null;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaParams);
                    var  payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                    jwt = Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);

                }

                return jwt;
        }

        static string FromHex(string hex) {
            hex = hex.Replace("-", "");
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            
            return Encoding.ASCII.GetString(raw);
        }

    }
}