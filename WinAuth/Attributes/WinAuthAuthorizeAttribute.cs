namespace WinAuth.Attributes
{
    public class WinAuthAuthorizeAttribute : Attribute
    {
        public string? Role {  get; private set; }

        public WinAuthAuthorizeAttribute(string? role = null)
        {
            Role = role;
        }
    }
}
