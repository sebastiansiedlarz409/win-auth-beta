using System.DirectoryServices.AccountManagement;

namespace WinAuth
{
    public class WinAuthCredentialValidator : IWinAuthCredentialValidator
    {
        public bool CheckCredential(string username, string password, string domain)
        {
            //using var context = new PrincipalContext(ContextType.Domain, domain);

            return true;// context.ValidateCredentials(username, password);
        }
    }
}
