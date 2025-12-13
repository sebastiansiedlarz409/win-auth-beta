namespace WinAuth.Attributes
{
    public class WinAuthAuthorizeAttribute : Attribute
    {
        public string? Role {  get; private set; }

        public bool Auth {  get; private set; }

        public WinAuthAuthorizeAttribute(bool auth = true, string? role = null)
        {
            Role = role;
            Auth = auth;
        }
    }
}
