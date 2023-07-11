using Csharpauth.Database;
using Csharpauth.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

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
               .AddEntityFrameworkStores<AppDbContext>() // this line adds relation between user and role
               .AddDefaultTokenProviders()
              ; // this line adds to email forget your password
            //

            // email sender
            services.AddTransient<IEmailSender, MailJetEmailSender>();
            //
            services.Configure<IdentityOptions>(option =>
            {
                option.Password.RequiredLength = 5;
                option.Password.RequireLowercase = true;
                option.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(30);
                option.Lockout.MaxFailedAccessAttempts = 3;
            });

            services.ConfigureApplicationCookie(options =>
            {
               options.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/Accessdenied");
            });

            // facebook injection 
            services.AddAuthentication().AddFacebook(options =>
            {
                options.AppId = "828039552096956";
                options.AppSecret = "8cc034dae5cea7a560b609d2c49fd565";
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