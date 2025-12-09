using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
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
        public async Task<IActionResult> Login()
        {
            if((await _authManager.IsSessionAliveAsync(HttpContext)))
            {
                return RedirectToAction("Page");
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LoginUser(string user, string pass)
        {
            if ((await _authManager.IsSessionAliveAsync(HttpContext)))
            {
                return RedirectToAction("Page");
            }
            if (_authManager.Login(user, pass))
            {
                await _authManager.CreateSessionAsync(HttpContext, user);

                return RedirectToAction("Page"); //login succeed - go to protected page
            }

            return RedirectToAction("Login"); //login failed - go to login page
        }

        //clear session
        [WinAuthAuthorize]
        public async Task<IActionResult> Logout()
        {
            await _authManager.KillSessionAsync(HttpContext);

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
