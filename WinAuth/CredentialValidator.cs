using System.DirectoryServices.AccountManagement;

namespace WinAuth
{
    public class CredentialValidator : ICredentialValidator
    {
        public bool CheckCredential(string username, string password, string domain)
        {
            using var context = new PrincipalContext(ContextType.Domain, domain);

            return context.ValidateCredentials(username, password);
        }
    }
}
