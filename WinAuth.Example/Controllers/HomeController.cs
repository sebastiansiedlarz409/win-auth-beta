using Microsoft.AspNetCore.Mvc;
using WinAuth.Attributes;
using WinAuth.Example.Auth;

namespace WinAuth.Example.Controllers
{
    public class HomeController : Controller
    {
        private WinAuthManager _authManager;

        public HomeController(WinAuthManager authManager)
        {
            _authManager = authManager;
        }

        //forbidden page
        //winauth redirect here when user role not allowe him access other action
        [WinAuthAccess(WinAuthAccess.Forbidden)]
        public IActionResult Forbidden()
        {
            return View();
        }

        //login page
        //winauth redirect here when use try to access nonpublic page without valid session
        [WinAuthAccess(WinAuthAccess.Login)]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult LoginUser(string user, string pass)
        {
            if (_authManager.Login(user, pass))
            {
                _authManager.CreateSession(HttpContext, user);
                return RedirectToAction("Page"); //login succeed - go to protected page
            }

            return RedirectToAction("Login"); //login failed - go to login page
        }

        //clear session
        [WinAuthAccess(WinAuthAccess.Authorized)]
        public IActionResult Logout()
        {
            _authManager.KillSession(HttpContext);

            return RedirectToAction("Index");
        }

        //non public page
        [WinAuthAccess(WinAuthAccess.Authorized)]
        public IActionResult Page()
        {
            return View();
        }

        //admin page
        [WinAuthAccess(WinAuthAccess.Authorized, "ADMIN")]
        public IActionResult Admin()
        {
            return View();
        }

        //public page
        public IActionResult Index()
        {
            return View();
        }
    }
}
