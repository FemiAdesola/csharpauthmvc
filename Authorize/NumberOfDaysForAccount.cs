using Csharpauth.Database;

namespace Csharpauth.Authorize
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly AppDbContext _context;
        public NumberOfDaysForAccount(AppDbContext context)
        {
            _context = context;
        }
        public int Get(string userId)
        {
            var user = _context.AppUsers.FirstOrDefault(u => u.Id == userId);
            if(user!=null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}