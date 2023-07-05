using Csharpauth.Database;
using Csharpauth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Csharpauth.Controllers
{
    public class AppUserController : BaseApiController
    {
        private readonly UserManager<IdentityUser> _userManager;
         private readonly SignInManager<IdentityUser> _signInManager;
        private readonly AppDbContext _context;
         public AppUserController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            AppDbContext context

            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
        }
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult>Register(Register model)
        {

            if(ModelState.IsValid)
            {
                var user = new AppUser { 
                    UserName = model.Email, 
                    Email = model.Email, 
                    Name = model.Name 
                    };
                
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            return View(model);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}