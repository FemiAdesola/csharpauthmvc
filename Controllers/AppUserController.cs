using Csharpauth.Models;
using Microsoft.AspNetCore.Mvc;

namespace Csharpauth.Controllers
{
    public class AppUserController : BaseApiController
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult>Register()
        {
            // var queryable = _context.AppUsers.AsQueryable();
            // var result = await queryable.ToListAsync();

            Register register = new Register();
            return View(register);
        }
    }
}