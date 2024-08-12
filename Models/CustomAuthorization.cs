using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

public class CustomAuthorization : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var controllerName = context.RouteData.Values["controller"]?.ToString();
        var actionName = context.RouteData.Values["action"]?.ToString();

        if (!context.HttpContext.User.Identity.IsAuthenticated && !(controllerName == "Home" && actionName == "Index"))
        {
            context.Result = new RedirectToActionResult("Forbidden", "Authentication", null);
        }
        else if (context.HttpContext.User.Identity.IsAuthenticated)
        {
            var userRole = context.HttpContext.User.FindFirst(ClaimTypes.Role)?.Value;

            if (userRole == "Customer" && (controllerName == "AdminDashboard" || controllerName == "Brands" || controllerName == "Categories"
                || controllerName == "Colors" || controllerName == "ItemCategories" || controllerName == "ItemImages" || controllerName == "Items"
                || controllerName == "ItemSizes" || controllerName == "ItemTags" || controllerName == "Roles"
                || controllerName == "ShippingPolicies" || controllerName == "Sizes" || controllerName == "Users"
                || controllerName == "Tags" || controllerName == "VoucherCodes"
                ))
            {
                context.HttpContext.Response.StatusCode = 403; // Set forbidden status
                context.Result = new ContentResult
                {
                    Content = "Forbidden",
                    ContentType = "text/plain",
                    StatusCode = 403
                };
            }
        }

        base.OnActionExecuting(context);
    }
}
