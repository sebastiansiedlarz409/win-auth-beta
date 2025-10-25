using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using WinAuth.Attributes;
using WinAuth.Example.Models;

namespace WinAuth.Example.Controllers
{
    public class HomeController : Controller
    {
        private WinAuthManager _authManager;

        public HomeController(WinAuthManager authManager)
        {
            _authManager = authManager;
        }

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

        [WinAuthAccess(WinAuthAccess.Authorized)]
        public IActionResult Logout()
        {
            _authManager.KillSession(HttpContext);

            return RedirectToAction("Index");
        }

        [WinAuthAccess(WinAuthAccess.Authorized)]
        public IActionResult Page()
        {
            return View();
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
