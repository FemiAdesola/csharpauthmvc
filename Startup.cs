using Csharpauth.Database;
using Microsoft.AspNetCore.Identity;

namespace Csharpauth
{
    public class Startup
    {
         public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }

         public void ConfigureServices(IServiceCollection services)
         {
            services.AddDbContext<AppDbContext>();
            services.AddControllers();
            services.AddControllersWithViews();
            services.AddRazorPages();

            // for adding identity user and roles
            services.AddIdentity<IdentityUser, IdentityRole>()
               .AddEntityFrameworkStores<AppDbContext>(); // this line adds relation between user and role
            //

            services.Configure<IdentityOptions>(option =>
            {
                option.Password.RequiredLength = 5;
                option.Password.RequireLowercase = true;
                option.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(30);
                option.Lockout.MaxFailedAccessAttempts = 3;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //Configure the HTTP request pipeline.
                if (env.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                }
                else
                {
                    app.UseExceptionHandler("/Home/Error");
                    app.UseHsts();
                }
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                 endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
       
        }
    }
}