# WinAuth 0.2 Beta :lock:

Its simple library for ASP.NET CORE combining authorization/authentication via the Windows domain and a cookie-based session-like mechanism.

## Setup :black_nib:

Create login and logout handlers:
```csharp
//only not authorized
[WinAuthAuthorize(false)]
public async Task<IActionResult> Login()
{
    return View();
}

//only not authorized
[HttpPost]
[WinAuthAuthorize(false)]
public async Task<IActionResult> LoginUser(string user, string pass)
{
    if (_authManager.Login(user, pass))
    {
        await _authManager.CreateSessionAsync(HttpContext, user);

        return RedirectToAction("Page"); //login succeed - go to protected page
    }

    return RedirectToAction("Login"); //login failed - go to login page
}

//authorization required
[WinAuthAuthorize]
public async Task<IActionResult> Logout()
{
    await _authManager.KillSessionAsync(HttpContext);

    return RedirectToAction("Index");
}
```

Create own session storage mechanism by implementing IWinAuthSessionStorage and register it in DI.
```csharp
public interface IWinAuthSessionStorage
{
    Task StoreSessionAsync(WinAuthSession session);
    Task UpdateSessionAsync(WinAuthSession session);
    Task<WinAuthSession?> GetSessionAsync(Guid sessionId);
    Task RemoveSessionAsync(WinAuthSession session);
}

//program.cs
//register it before calling AddWinAuth()
builder.Services.AddSingleton<IWinAuthSessionStorage, WinAuthSessionMemoryStorage>();
```

OPTIONAL: Create own role provider mechanism by implementing IWinAuthRoleProvider and register it in DI. By default there is no role provider - all actions with specified role will be freely available.
```csharp
public interface IWinAuthRoleProvider
{
    Task<string?> GetRoleAsync(WinAuthSession session);
    Task<bool> HasAccessAsync(WinAuthSession session, string role);
}

//program.cs
//register it before calling AddWinAuth()
builder.Services.AddSingleton<IWinAuthRoleProvider, WinAuthRoleProvider>();
```

OPTIONAL: Create own access denied handler by implementing IWinAuthAccessDeniedHandler
```csharp
public interface IWinAuthAccessDeniedHandler
{
    Task RequireAuthenticated(HttpContext httpContext); //handle request when unauthorized user try access authorized required page
    Task RequireUnAuthenticated(HttpContext httpContext); //handle request when authorized user try access unauthorized required page
    Task RequireRole(HttpContext httpContext, string? userRole, string requiredRole); //handle request when authorized user try access page that require higher role in application
}

//program.cs
//register it before calling AddWinAuth()
builder.Services.AddSingleton<IWinAuthAccessDeniedHandler, WinAuthAccessDeniedHandler>();
```

Configure DI and Middleware
```csharp
//program.cs
//register what is neccessary
builder.Services.AddWinAuth("domain.local" /*DOMAIN NAME*/, 30 /*SESSION LIFETIME IN MINUTES*/);
...
//base asp routing setup
app.UseRouting();
...
//use middleware after routing after routing
app.UseWinAuth(typeof(Program).Assembly /*MVC ASSEMBLY*/);

```

# Using :tada:

Mark your controllers actions like this using attribute:
```csharp
//free access page
public IActionResult Index()
{
    return View();
}

//only unauthorized users
[WinAuthAuthorize(false)]
public IActionResult Page1()
{
    return View();
}

//authorization required
[WinAuthAuthorize]
public IActionResult Page2(int id)
{
    return View();
}

//authorization required, admin role required
[WinAuthAuthorize(true, "ADMIN")]
public IActionResult Page3()
{
    return View();
}
```

Checking if authenticated in razor

```csharp
@inject WinAuth.WinAuthManager authManager

//...

@{
    string? role = (await authManager.GetUserRole(ViewContext.HttpContext))?.ToString();
    bool isAuthenticated = await authManager.IsAuthenticated(ViewContext.HttpContext);
    string? userName = await authManager.GetUserName(ViewContext.HttpContext);
}
```