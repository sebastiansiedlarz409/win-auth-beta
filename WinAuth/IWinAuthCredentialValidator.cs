namespace WinAuth
{
    public interface IWinAuthCredentialValidator
    {
        public bool CheckCredential(string username, string password, string domain);
    }
}
