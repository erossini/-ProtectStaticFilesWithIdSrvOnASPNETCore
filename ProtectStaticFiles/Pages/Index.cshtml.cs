﻿using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace ProtectStaticFilesWithAuth.Pages
{
    public class IndexModel : PageModel
    {
        private readonly string SignInScheme;

        public IndexModel(IOptions<AuthenticationOptions> options)
        {
            this.SignInScheme = options.Value.DefaultScheme;
        }

        public async Task<IActionResult> OnPost(string command)
        {
            switch (command)
            {
                case "Sign in":
                    return Redirect("/Login");

                case "Sign out":
                    await this.HttpContext.SignOutAsync();
                    return Redirect("/");

                default: throw new Exception($"Unknown command: \"{command}\"");
            }
        }
    }
}
