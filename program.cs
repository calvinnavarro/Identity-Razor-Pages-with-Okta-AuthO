
using AspNetCoreHero.ToastNotification;
using LA.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using LAMHOMS.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Auth0.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<LADbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("LAConnection"));
    LADbContext.ConnectionString = builder.Configuration.GetConnectionString("LAConnection");

}, ServiceLifetime.Transient);

//builder.Services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<LADbContext>();
builder.Services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<LADbContext>()
        .AddDefaultTokenProviders();


builder.Services.Configure<IdentityOptions>(opts =>
{
    opts.SignIn.RequireConfirmedEmail = true;
});
 builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/Forbidden/";
    }); 
 builder.Services.AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = builder.Configuration["Auth0:Domain"];
        options.ClientId = builder.Configuration["Auth0:ClientId"];
        options.SkipCookieMiddleware = true;
        options.Scope = "openid profile email";
    });

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Account/Signout");
    options.Conventions.AuthorizePage("/Account/Manage");

    options.Conventions.AuthorizePage("/Account/Logout");
    options.Conventions.AuthorizePage("/Account/Profile");

    options.Conventions.AddPageRoute("/Initial", "/");
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

});

builder.Services.AddTransient<IEmailSender, MailKitEmailSender>();
builder.Services.Configure<MailKitEmailSenderOptions>(options =>
{
    options.Host_Address = "smtp.ucsd.edu";
    options.Host_Port = 587;
    options.Host_Username = "hsrcwebmaster@ucsd.edu";
    options.Host_Password = "6A!ae0da692a192a2869d2672eb11114";
    options.Sender_EMail = "hsrcwebmaster@ucsd.edu";
    options.Sender_Name = "LA iHOMS";
});
builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);

    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
    options.SlidingExpiration = true;
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

//add roles
using(var scope=app.Services.CreateScope())
{
    var roleManager=
        scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    var roles = new[] { "Admin", "Manager", "Member" };
    
    foreach(var role in roles)
    {
        if(!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }

}
// create admin user 
using (var scope = app.Services.CreateScope())
{
    var userManager =
        scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    string email = "admin@admin.com";
    string password = "Defaul9@";
    if (await userManager.FindByEmailAsync(email) == null)
    {
        var user = new ApplicationUser();
        user.UserName = email;
        user.Email = email;
        user.SecuritySalt = password;

        await userManager.CreateAsync(user, password);
        await userManager.AddToRoleAsync(user, "Admin");
    }


}
app.Run();
