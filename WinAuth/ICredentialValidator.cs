namespace WinAuth
{
    public interface ICredentialValidator
    {
        public bool CheckCredential(string username, string password, string domain);
    }
}
