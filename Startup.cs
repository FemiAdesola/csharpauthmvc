using Csharpauth.Authorize;
using Csharpauth.Database;
using Csharpauth.Service;
using Microsoft.AspNetCore.Authorization;
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

            // for adding authroization policy 
             services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin")
                    .RequireRole("User"));
                options.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin")
                    .RequireClaim("create", "True"));
                
                options.AddPolicy("Admin_Create_Edit_DeleteAccess", policy => policy.RequireRole("Admin")  
                    .RequireClaim("create", "True")
                    .RequireClaim("edit", "True")
                    .RequireClaim("Delete", "True"));

                options.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdmin", policy => policy.RequireAssertion(context =>
                AuthorizeAdminWithClaimsOrSuperAdmin(context)));

                //  options.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdmin", policy => policy.RequireAssertion(context =>(
                //     context. User.IsInRole("Admin") && context.User.HasClaim(c => c.Type =="Create" && c.Value =="True")
                //     && context.User.HasClaim(c => c.Type =="Edit" && c.Value =="True")
                //     && context.User.HasClaim(c => c.Type =="Delete" && c.Value =="True")
                //  ) || context.User.IsInRole("SuperAdmin")
                // ));

                options.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements
                    .Add(new OnlySuperAdminChecker()));
                options.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements
                    .Add(new AdminWithMoreThan1000DaysRequirement(1000)));
                    // for use firtname
                options.AddPolicy("FirstNameAuth", policy => policy.Requirements
                    .Add(new FirstNameAuthRequirement("Femi")));
            });


            // for get number of days from user account 
            services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
            services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();
            services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
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

        private bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
        {
            return (context.User.IsInRole("Admin") 
                && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
                && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
                && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
            ) || context.User.IsInRole("SuperAdmin");
        }
    }
}