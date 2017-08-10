using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;

namespace AStar.Util
{
    public class LittleEndian
    {
        public static string toBigEndian(string littleEndian)
        {
            var output = new SoapHexBinary(SoapHexBinary.Parse(littleEndian).Value.Reverse().ToArray()).ToString();
            return output;
        }
    }
}