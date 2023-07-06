namespace Csharpauth.Service
{
    public class MailJetOptions
    {
        public string ApiKey { get; set; } = null!; // property name come from appsettings
        public string SecretKey { get; set; } = null!;
    }
}