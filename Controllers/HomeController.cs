using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Controllers;

public sealed class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    [HttpGet]
    public IActionResult Error()
    {
        Response.StatusCode = StatusCodes.Status500InternalServerError;
        return View();
    }
}
