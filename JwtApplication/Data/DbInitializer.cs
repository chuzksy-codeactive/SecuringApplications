using JwtApplication.Domain;
using JwtApplication.Enums;
using JwtApplication.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Extensions;

namespace JwtApplication.Data
{
    public static class DbInitializer
    {
        /// <summary>
        /// This role seeds a basic platform roles on start of the application
        /// </summary>
        /// <param name="host"></param>
        /// <returns></returns>
        public static async Task SeedRole(this IHost host)
        {
            var serviceProvider = host.Services.CreateScope().ServiceProvider;
            var context = serviceProvider.GetRequiredService<AppDbContext>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<Role>>();

            #region Create Roles and Add Super Admin User to Role
            var rolesEnumList = EnumExtension.GetEnumResults<ERole>();
            if (rolesEnumList.Any())
            {
                foreach (var item in rolesEnumList)
                {
                    var roleRecord = context.Roles.Where(x => x.Name.Equals(item.Name));

                    if (roleRecord.FirstOrDefault()?.Name == null)
                    {

                        Role role = new Role()
                        {
                            ConcurrencyStamp = Guid.NewGuid().ToString(),
                            Name = item.Name
                        };
                        await roleManager.CreateAsync(role);

                    }
                }
            }
            #endregion
        }


        /// <summary>
        /// This method create seed data : super user who administrates the platform
        /// </summary>
        /// <param name="host"></param>
        /// <returns></returns>
        public static async Task Seed(this IHost host)
        {
            using var scope = host.Services.CreateScope();
            var serviceProvider = scope.ServiceProvider;

            var context = serviceProvider.GetRequiredService<AppDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<User>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<Role>>();

            await context.Database.EnsureCreatedAsync();

            var query = context.Set<User>().AsQueryable();

            var emails = new string[] { "admin@admin.com" };
            foreach (var email in emails)
            {
                var getUser = await query.IgnoreQueryFilters().FirstOrDefaultAsync(x => x.UserName.Equals(email));

                if (getUser == null)
                {
                    var newUser = new User
                    {
                        FirstName = "Admin",
                        LastName = "Admin",
                        SecurityStamp = Guid.NewGuid().ToString(),
                        EmailConfirmed = true,
                        TwoFactorEnabled = false,
                        PhoneNumberConfirmed = false,
                        LockoutEnabled = false,
                        CreatedAt = DateTime.UtcNow,
                        Email = email,
                        UserName = email,
                        Verified = true,
                        IsActive = true,
                        PhoneNumber = "07036HRMS000",
                    };

                    var result = await userManager.CreateAsync(newUser, "Admin123@");
                    var systemAdminrole = ERole.SUPERADMIN.ToString();
                    if (!(await userManager.IsInRoleAsync(newUser, systemAdminrole)))
                    {
                        await userManager.AddToRoleAsync(newUser, systemAdminrole);
                    }
                }
            }
        }
    }
}
