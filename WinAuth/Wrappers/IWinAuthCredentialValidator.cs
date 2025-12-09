namespace WinAuth.Wrappers
{
    public interface IWinAuthCredentialValidator
    {
        bool CheckCredential(string username, string password, string domain);
    }
}
