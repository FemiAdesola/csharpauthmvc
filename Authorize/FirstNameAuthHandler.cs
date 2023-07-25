using System.Security.Claims;
using Csharpauth.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Csharpauth.Authorize
{
    public class FirstNameAuthHandler : AuthorizationHandler<FirstNameAuthRequirement>
    {
        public UserManager<IdentityUser> _userManager { get; set; }
        public AppDbContext _context { get; set; }
         public FirstNameAuthHandler(UserManager<IdentityUser> userManager, AppDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameAuthRequirement requirement)
        {
            string userid = context.User.FindFirst(ClaimTypes.NameIdentifier)!.Value;
            var user = _context.AppUsers.FirstOrDefault(u => u.Id == userid);
            var claims = Task.Run(async () => await _userManager.GetClaimsAsync(user!)).Result;
            var claim = claims.FirstOrDefault(c => c.Type == "FirstName");
            if (claim != null)
            {
                if (claim.Value.ToLower().Contains(requirement.Name.ToLower()))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
            }
            return Task.CompletedTask;
        }
    }
}