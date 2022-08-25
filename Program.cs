using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace httpsTest001
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                HostConfig.CertPath = context.Configuration["CertPath"];
                HostConfig.CertPassword = context.Configuration["CertPassword"];
            })
            .ConfigureWebHostDefaults(webBuilder =>
            {
                var host = Dns.GetHostEntry("h5sebastian.dk");
                webBuilder.ConfigureKestrel(opt =>
                {
                    opt.Listen(host.AddressList[0], 5000);
                    opt.Listen(host.AddressList[0], 5001, listOpt =>
                    {
                        listOpt.UseHttps(HostConfig.CertPath, HostConfig.CertPassword);
                    });
                });
                webBuilder.UseStartup<Startup>();
            });
    }

    public static class HostConfig
    {
        public static string CertPath { get; set; }
        public static string CertPassword { get; set; }
    }
}
