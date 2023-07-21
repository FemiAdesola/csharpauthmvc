using Csharpauth.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Csharpauth.Models;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Csharpauth.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;

        public UserController(
            UserManager<IdentityUser> userManager,
            AppDbContext context
            )
        {
            _userManager = userManager;
            _context = context;

        }
        public IActionResult Index()
        {
            var userList = _context.AppUsers.ToList();
            var userRole = _context.UserRoles.ToList();
            var roles = _context.Roles.ToList();
            foreach(var user in userList)
            {
                var role = userRole.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId)!.Name!;
                }
            }

            return View(userList);
        }

        // for edit user by id
        public IActionResult Edit(string userId)
        {
            var objFromDb = _context.AppUsers.FirstOrDefault(user=>user.Id==userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            var userRole = _context.UserRoles.ToList();
            var roles = _context.Roles.ToList();
            var role = userRole.FirstOrDefault(user => user.UserId == objFromDb.Id);
            if (role != null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(user => user.Id == role.RoleId)!.Id;
            }
            objFromDb.RoleList = _context.Roles.Select(user => new SelectListItem
            {
                Text = user.Name,
                Value = user.Id
            });
            return View(objFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(AppUser user)
        {
            if (ModelState.IsValid)
            {
                var objFromDb = _context.AppUsers.FirstOrDefault(u => u.Id == user.Id);
                if (objFromDb == null)
                {
                    return NotFound();
                }
                // about the previous role
                var userRole = _context.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
                if (userRole != null)
                {
                    var previousRoleName = _context.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    
                    //how to remove previous role
                    await _userManager.RemoveFromRoleAsync(objFromDb, previousRoleName!);
                }

                //how to add new role
                await _userManager.AddToRoleAsync(objFromDb, _context.Roles.FirstOrDefault(u => u.Id == user.RoleId)!.Name!);
                objFromDb.Name = user.Name;
                _context.SaveChanges();
                TempData[StaticToarst.Success] = "User has been edited successfully.";
                return RedirectToAction(nameof(Index));
            }


            user.RoleList = _context.Roles.Select(u => new SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(user);
        }
    }
}