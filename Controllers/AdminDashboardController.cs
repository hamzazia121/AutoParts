using AutoPartsHub.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AutoPartsHub.Controllers
{

	[CustomAuthorization]
	[Authorize(Roles = "Admin")]
	public class AdminDashboardController : Controller
	{
		private readonly AutoPartsHubContext _context;
		public AdminDashboardController(AutoPartsHubContext context)
		{
			_context = context;
		}
		public async Task<IActionResult> Index()
		{
			CheckoutViewModel checkoutView = new CheckoutViewModel();
			try
			{

				if (User.Identity.IsAuthenticated)
				{
					var userIdString = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

					if (!string.IsNullOrEmpty(userIdString) && int.TryParse(userIdString, out int userId))
					{

						var order = checkoutView.TblOrdersMain = await _context.TblOrdersMains
			 .Include(x => x.User)
			 .Include(x => x.City)
			 .FirstAsync(x => x.UserId == userId);
						// Get today's orders
						checkoutView.OrderDetails = await _context.TblOrderDetails
		.Include(x => x.OrderMain)
			.ThenInclude(x => x.User)
			.ThenInclude(u => u.Roll)
		.Include(x => x.OrderMain)
			.ThenInclude(x => x.Status)
		.Include(x => x.Item)
			.ThenInclude(i => i.TblItemImages)
		.ToListAsync();
						checkoutView.TodayOrderDetails = await _context.TblOrderDetails
							.Include(x => x.OrderMain)
			.ThenInclude(x => x.User)
			.ThenInclude(u => u.Roll)
		.Include(x => x.OrderMain)
			.ThenInclude(x => x.Status)
		.Include(x => x.Item)
			.ThenInclude(i => i.TblItemImages)
							.Where(x => x.OrderMain.OrderDate == DateTime.Today)
		.ToListAsync();

					}
				}


			}
			catch (Exception ex)
			{
				return View(ex.Message);
			}

			ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
			ViewData["CityId"] = new SelectList(_context.TblCities, "CityId", "CityName");
			ViewData["UserId"] = new SelectList(_context.TblUsers, "UserId", "UserName");
			ViewData["Status"] = new SelectList(_context.TblStatuses, "StatusId", "StatusName");

			return View(checkoutView);
		}
	}
}
