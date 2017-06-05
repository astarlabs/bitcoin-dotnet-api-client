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
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace AStar.Util
{
    public class Token
    {
        
        public static string sign(string privateKeyString){

            var iat = (Int64)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            var exp = (Int64)(DateTime.UtcNow.AddMinutes(10).Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            RandomNumberGenerator rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[64];
            rng.GetBytes(bytes);
            
            var hex = FromHex(privateKeyString);

            Dictionary<string, object> claims = new Dictionary<string, object>();
            claims.Add("exp", exp);
            claims.Add("iat", iat);
            claims.Add("jti", new BigInteger(bytes).ToString());

            var token = CreateToken(claims, hex);

            Console.WriteLine(token);

            return token;

        }

        public static string CreateToken(Dictionary<string, object> claims, string privateKey)
            { 

                //Console.WriteLine(privateKey);

                string jwt = string.Empty;
                AsymmetricCipherKeyPair key;

                using (StringReader sr = new StringReader(privateKey))
                {
                    PemReader pr = new PemReader(sr);
                    key = (AsymmetricCipherKeyPair)pr.ReadObject();
                }

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)key.Private);

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
                {
                    rsa.ImportParameters(rsaParams);
                    jwt = Jose.JWT.Encode(claims, rsa, Jose.JwsAlgorithm.RS256);

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