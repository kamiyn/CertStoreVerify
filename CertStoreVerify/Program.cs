using System;
using Newtonsoft.Json;

namespace CertStoreVerify
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var repo = new Verifier();
            var result = repo.Do();

            Console.WriteLine(JsonConvert.SerializeObject(result, Formatting.Indented));
        }
    }
}
