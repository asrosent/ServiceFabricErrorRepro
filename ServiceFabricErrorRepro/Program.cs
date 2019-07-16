using CommandLine;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Fabric;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ServiceFabricErrorRepro
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var parserResult = Parser.Default.ParseArguments<Arguments>(args);
            if (parserResult.Tag == ParserResultType.NotParsed)
            {
                Environment.Exit(1);
            }

            Arguments arguments = null;
            parserResult.WithParsed(_ => arguments = _);

            var token = 
                await new AuthenticationContext($"https://login.microsoftonline.com/{arguments.TenantId.ToLower()}").
                    AcquireTokenAsync(
                        arguments.ServiceFabricClusterApplicationId.ToLower(),
                        new ClientAssertionCertificate(
                            arguments.ClientId.ToLower(),
                            GetCertificate(
                                arguments.CertificateStoreName,
                                arguments.CertificateStoreLocation,
                                arguments.CertificateThumbprint)));

            var connectionEndpoint = 
                new DnsEndPoint(
                    arguments.ServiceFabricManagementDnsName,
                    arguments.ServiceFabricClientConnectionEndpointPort);

            var claimsCredentials = new ClaimsCredentials();
            claimsCredentials.ServerCommonNames.Add(connectionEndpoint.Host);
            claimsCredentials.LocalClaims = token.AccessToken;

            using (var client = new FabricClient(claimsCredentials,$"{connectionEndpoint.Host}:{connectionEndpoint.Port}"))
            {
                await client.QueryManager.GetApplicationListAsync();
            }

            Console.WriteLine("Everything Works!");
        }



        private static X509Certificate2 GetCertificate(
            StoreName storeName,
            StoreLocation storeLocation,
            string thumbprint)
        {
            using (var store = new X509Store(storeName,storeLocation))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                
                return store.Certificates.
                    Find(X509FindType.FindByThumbprint, thumbprint, false).
                    Cast<X509Certificate2>().
                    Single();
            }
        }
    }

    public class Arguments
    {
        [Option("CertificateThumbprint", Required = true, HelpText = "Thumprint of the certificate used to authenticate your AAD application")]
        public string CertificateThumbprint { get; set; }
        [Option("ClientId", Required = true, HelpText = "Your AAD application ID")]
        public string ClientId { get; set; }
        [Option("TenantId", Required = true, HelpText = "Your Tenant ID")]
        public string TenantId { get; set; }
        [Option("ServiceFabricClientConnectionEndpointPort", Required = true, HelpText = "Your Service Fabric Client Connection Endpoint Port")]
        public int ServiceFabricClientConnectionEndpointPort { get; set; }
        [Option("ServiceFabricManagementDnsName", Required = true, HelpText = "Your Service Fabric Management Dns Name (for example: Administration.test.org)")]
        public string ServiceFabricManagementDnsName { get; set; }
        [Option("ServiceFabricClusterApplicationId", Required = true, HelpText = "Your Service Fabric Cluster Application Id")]
        public string ServiceFabricClusterApplicationId { get; set; }
        [Option("CertificateStoreLocation", Required = true, HelpText = "Store Location of the certificate used to authenticate your AAD application (for example: LocalMachine")]
        public StoreLocation CertificateStoreLocation { get; set; }
        [Option("CertificateStoreName", Required = true, HelpText = "Store Name Location of the certificate used to authenticate your AAD application (for example: My)")]
        public StoreName CertificateStoreName { get; set; }
    }

}
