using Microsoft.AspNetCore.Mvc;
using WinAuth.Attributes;

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
        public IActionResult Forbidden()
        {
            return View();
        }

        //login page
        //winauth redirect here when use try to access nonpublic page without valid session
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult LoginUser(string user, string pass)
        {
            if (_authManager.Login(user, pass))
            {
                _authManager.CreateSessionAsync(HttpContext, user);

                return RedirectToAction("Page"); //login succeed - go to protected page
            }

            return RedirectToAction("Login"); //login failed - go to login page
        }

        //clear session
        [WinAuthAuthorize]
        public IActionResult Logout()
        {
            _authManager.KillSessionAsync(HttpContext);

            return RedirectToAction("Index");
        }

        //non public page
        [WinAuthAuthorize]
        public IActionResult Page()
        {
            return View();
        }

        //admin page
        [WinAuthAuthorize("ADMIN")]
        public IActionResult Admin()
        {
            return View();
        }

        [WinAuthAuthorize("ADMIN")]
        [HttpPost]
        public IActionResult Admin(string name)
        {
            ViewBag.Name = name;

            return View();
        }

        //public page
        public IActionResult Index()
        {
            return View();
        }
    }
}
