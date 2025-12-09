using WinAuth.Wrappers;

namespace WinAuth.Tests.Integration
{
    internal class WinAuthTestCredentialValidator : IWinAuthCredentialValidator
    {
        public bool CheckCredential(string username, string password, string domain)
        {
            return true;
        }
    }
}
