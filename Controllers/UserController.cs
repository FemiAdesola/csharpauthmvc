using Csharpauth.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Csharpauth.Models;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using static Csharpauth.Models.UserClaim;
using Microsoft.AspNetCore.Authorization;

namespace Csharpauth.Controllers
{

    [Authorize (Roles = "SuperAdmin")]
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

        // for locking users
        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = _context.AppUsers.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            if(objFromDb.LockoutEnd!=null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked untill lockoutend time
                //clicking on this action will unlock them
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[StaticToarst.Success] = "User unlocked successfully.";
            }
            else
            {
                //user is not locked, and we want to lock the user
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[StaticToarst.Success] = "User locked successfully.";
            }
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        // for deleteing users
        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var objFromDb = _context.AppUsers.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            _context.AppUsers.Remove(objFromDb);
            _context.SaveChanges();
            TempData[StaticToarst.Success] = "User deleted successfully.";
            return RedirectToAction(nameof(Index));
        }

        // user claims
        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await _userManager.GetClaimsAsync(user); // for existingUserClaims

            var model = new UserClaim()
            {
                UserId = userId
            };

            foreach(Claim claim in UserClaimData.claimsList)
            {
                UserClaims userClaim = new UserClaims
                {
                    ClaimType = claim.Type
                };

                if (existingUserClaims.Any(c => c.Type == claim.Type)) // for existingUserClaims
                {
                    userClaim.IsSelected = true;
                }

                model.Claims.Add(userClaim);
            }

            return View(model);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaim userClaim)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userClaim.UserId);

            if (user == null)
            {
                return NotFound();
            }

            var claims = await _userManager.GetClaimsAsync(user); // for get all the claims
            var result = await _userManager.RemoveClaimsAsync(user,claims);

            if (!result.Succeeded)
            {
                TempData[StaticToarst.Error] = "Error while removing claims";
                return View(userClaim);
            }

            result = await _userManager.AddClaimsAsync(user,
                userClaim.Claims.Where(c => c.IsSelected)
                .Select(c => new Claim(c.ClaimType, c.IsSelected.ToString()))
                );

            if (!result.Succeeded)
            {
                TempData[StaticToarst.Error] = "Error while adding claims";
                return View(userClaim);
            }

            TempData[StaticToarst.Success] = "Claims updated successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}