using System;
using System.IO;
using System.Net;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using ProtectStaticFilesWithAuth.Models;

namespace ProtectStaticFilesWithAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRazorPages(options => {
                options.Conventions.AuthorizePage("/Login");
            });

            services.Configure<IdentityServerConfiguration>(Configuration.GetSection("IdentityServerConfiguration"));

            services.AddDistributedMemoryCache();

            services.AddSession(options =>
            {
                options.Cookie.Name = ".psc.Session";
                options.IdleTimeout = TimeSpan.FromHours(12);
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                options.Cookie.Name = "psc.dashboard";
            })
            .AddOpenIdConnect("oidc", options =>
            {
                IdentityServerConfiguration idsrv = Configuration.GetSection("IdentityServerConfiguration").Get<IdentityServerConfiguration>();
                options.Authority = idsrv.Url;
                options.ClientId = idsrv.ClientId;
                options.ClientSecret = idsrv.ClientSecret;

#if DEBUG
                options.RequireHttpsMetadata = false;
#else
                options.RequireHttpsMetadata = true;
#endif

                options.ResponseType = "code";

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("roles");
                options.Scope.Add("offline_access");

                options.ClaimActions.MapJsonKey("role", "role", "role");

                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;

                options.SignedOutRedirectUri = "/";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.Name,
                    RoleClaimType = JwtClaimTypes.Role,
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();

            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(Path.Combine(env.ContentRootPath, "secretfiles")),
                RequestPath = "/protectedfiles",
                OnPrepareResponse = ctx =>
                {
                    if (ctx.Context.Request.Path.StartsWithSegments("/protectedfiles"))
                    {
                        ctx.Context.Response.Headers.Add("Cache-Control", "no-store");

                        if (!ctx.Context.User.Identity.IsAuthenticated)
                        {
                            // respond HTTP 401 Unauthorized with empty body.
                            ctx.Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            ctx.Context.Response.ContentLength = 0;
                            ctx.Context.Response.Body = Stream.Null;

                            // - or, redirect to another page. -
                            // ctx.Context.Response.Redirect("/");
                        }
                    }
                }
            });

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }
}
