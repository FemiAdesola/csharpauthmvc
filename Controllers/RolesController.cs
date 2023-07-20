using Csharpauth.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Csharpauth.Controllers
{
    public class RolesController: Controller
    {
         private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            AppDbContext context
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;

        }

        public IActionResult Index()
        {
            var roles = _context.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult UpdateInsert(string id)
        {
            if (String.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                //update
                // var roles = _context.Roles.ToList();
                var objFromDb = _context.Roles.FirstOrDefault(u => u.Id == id);
                return View(objFromDb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateInsert(IdentityRole roleObj)
        {
            if(await _roleManager.RoleExistsAsync(roleObj.Name!))
            { 
                //error
                TempData[StaticToarst.Error] = "Role already exists.";
                return RedirectToAction(nameof(Index));
            }
            if (string.IsNullOrEmpty(roleObj.Id))
            {
                //create
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[StaticToarst.Success] = "Role created successfully";
            }
            else
            {
                //update
                var objRoleFromDb = _context.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                if (objRoleFromDb == null)
                {
                    TempData[StaticToarst.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }
                objRoleFromDb.Name = roleObj.Name;
                objRoleFromDb.NormalizedName = roleObj.Name!.ToUpper();
                var result = await _roleManager.UpdateAsync(objRoleFromDb);
                TempData[StaticToarst.Success] = "Role updated successfully";
            }
            return RedirectToAction(nameof(Index));

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            // for checking roles
            var objFromDb = _context.Roles.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null)
            {
                TempData[StaticToarst.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }
            // for checking user roles
            var userRolesForThisRole = _context.UserRoles.Where(u => u.RoleId == id).Count();
            if (userRolesForThisRole > 0)
            {
                TempData[StaticToarst.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }
            
            // delete and return to role page
            await _roleManager.DeleteAsync(objFromDb);
            TempData[StaticToarst.Success] = "Role deleted successfully.";
            return RedirectToAction(nameof(Index));

        }
    }
}