using _Helper;
using AutoPartsHub.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Security.Claims;
using AutoPartsHub._Helper;

namespace AutoPartsHub.Controllers
{
    //[CustomAuthorization]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly AutoPartsHubContext _context;
        private readonly IMailService _mailService;
        public HomeController(ILogger<HomeController> logger, IMailService mailService, AutoPartsHubContext context)
        {
            _logger = logger;
            _context = context;
            _mailService = mailService;
        }



        public async Task<IActionResult> Index()
        {
            var items = await _context.TblItems.Include(x => x.TblItemImages).ToListAsync();
            return View(items);
        }
        [Route("privacy")]

        [Route("about")]
        public IActionResult About()
        {
            return View();
        }

        [Route("shop")]
        public async Task<IActionResult> Shop()
        {
            var items = await _context.TblItems.Include(t => t.TblItemImages).ToListAsync();
            return View(items);
        }


        [Route("blog")]
        public IActionResult Blog()
        {
            return View();
        }
    [HttpGet]
	[Route("myAccount")]
	public async Task<IActionResult> MyAccount()
	{
		var today = DateTime.Today;
		CheckoutViewModel checkoutView = new CheckoutViewModel();
            try
            {

		if (User.Identity.IsAuthenticated)
		{
			var userIdString = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

			if (!string.IsNullOrEmpty(userIdString) && int.TryParse(userIdString, out int userId))
			{

               var order =       checkoutView.TblOrdersMain = await _context.TblOrdersMains
    .Include(x => x.User)
    .Include(x => x.City)
    .FirstAsync(x => x.UserId == userId);
                    // Get today's orders
                checkoutView.OrderDetail = await _context.TblOrderDetails
					.Include(x=>x.OrderMain)
                    .Include(x => x.Item)
					.ThenInclude(x => x.TblItemImages)
					.Where(x => x.OrderMain.UserId == userId)
					.ToListAsync();
						checkoutView.TodayOrderDetail = await _context.TblOrderDetails
							.Include(x => x.OrderMain)
							.Include(x => x.Item)
							.ThenInclude(x => x.TblItemImages)
                            .Where(x=> x.OrderMain.UserId == userId && x.OrderMain.OrderDate==DateTime.Today )
							.ToListAsync();
						
					}
		}
            }catch(Exception ex)
            {
                return View(ex.Message);
            }

		ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
		ViewData["CityId"] = new SelectList(_context.TblCities, "CityId", "CityName");
		ViewData["UserId"] = new SelectList(_context.TblUsers, "UserId", "UserName");
        
		return View(checkoutView);
	}



	[Route("gallery")]
        public IActionResult Gallery()
        {
            return View();
        }


        //[Route("Pages")]
        public async Task<IActionResult> Cart()
        {


            List<TblItem> tblItems = new List<TblItem>();

            if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
            {
                var data = HttpContext.Request.Cookies["AutoHubCart"];
                var DecriptData = Protection.Decrypt(data);

                ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                if (listCartModel != null && listCartModel.Carts.Count > 0)
                {
                    List<int> ProductIds = listCartModel.Carts.Select(x => x.ProductId).ToList();

                    tblItems = (await _context.TblItems
                                      .Where(x => x.MDelete == false || x.MDelete == null)
                                      .Where(x => ProductIds.Contains(x.ItemId))
                                      .Include(t => t.Brand).Include(t => t.TblItemImages)
                                      .ToListAsync());

                    foreach (var item in tblItems)
                    {
                        var cartItem = listCartModel.Carts.FirstOrDefault(c => c.ProductId == item.ItemId);
                        if (cartItem != null)
                        {
                            item.Quantity = cartItem.Quantity;
                        }
                    }


                }
                else
                {

                }
            }



            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");

            return View(tblItems);
        }


        [Route("GetCartCount")]

        public async Task<IActionResult> GetCartCount()
        {
            try
            {

                int itemCount = 0;
                if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
                {
                    var data = HttpContext.Request.Cookies["AutoHubCart"];
                    var DecriptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                    itemCount = listCartModel.Carts.Count();
                }


                return Json(new { success = true, message = itemCount });


            }
            catch (Exception exp)
            {
                return Json(new { success = false, message = exp.Message });
            }


        }


        public async Task<IActionResult> ConfirmOrder(int id)
        {

            CheckoutViewModel checkoutView = new CheckoutViewModel();
			//checkoutView.TblOrdersMain.UserName = _context.TblUsers.
			checkoutView.TblOrdersMain = await _context.TblOrdersMains
	   .Include(x => x.User)
	   .Include(x => x.City).FirstAsync(x=>x.OrderId==id);

			checkoutView.OrderDetail = await _context.TblOrderDetails
                .Include(x => x.Item)
                .ThenInclude(x => x.TblItemImages)
                .Include(x => x.OrderMain)
                .Where(x => x.OrderMainId == id)
                .ToListAsync();
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            ViewData["CityId"] = new SelectList(_context.TblCities, "CityId", "CityName");
            ViewData["UserId"] = new SelectList(_context.TblUsers, "UserId", "UserName");

            return View(checkoutView);
        }


        public IActionResult ContactUS()
        {
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ContactUS([Bind("ContectUsId,ContectUsName,ContectUsEmail,ContectUsPhoneNo,ContectUsSubject,ContectUsMassage,mDelete")] TblContectU tblContact)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    _context.Add(tblContact);
                    await _context.SaveChangesAsync();

                }


                return View();
            }
            catch (Exception exp)
            {

                ViewBag.Message = exp.Message;
                return View(tblContact);
            }

        }


        [Route("itemDetail")]
        public async Task<IActionResult> ItemDetail(int id)
        {
            try
            {
                var item = await _context.TblItems
                    .Include(t => t.TblItemImages)
                    .FirstOrDefaultAsync(x => x.ItemId == id);

                if (item == null)
                {
                    return NotFound();
                }

                return View(item);
            }
            catch (Exception ex)
            {
                // Log the exception
                _logger.LogError(ex, "Error retrieving item details");

                // Optionally, return a custom error view or message
                return StatusCode(500, "Internal server error");
            }
        }

        // GET: Checkout

        [HttpGet("Checkout")]
        public async Task<IActionResult> Checkout()
        {
            try
            {
                List<TblItem> tblItems = new List<TblItem>();

                // Check if the cart cookie exists and contains data
                if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
                {
                    var data = HttpContext.Request.Cookies["AutoHubCart"];
                    var decryptedData = Protection.Decrypt(data);

                    var listCartModel = JsonConvert.DeserializeObject<ListCartModel>(decryptedData);

                    if (listCartModel != null && listCartModel.Carts.Any())
                    {
                        // Get product IDs from the cart
                        var productIds = listCartModel.Carts.Select(x => x.ProductId).ToList();

                        // Fetch items from the database based on product IDs
                        tblItems = await _context.TblItems
                            .Where(x => x.MDelete == false || x.MDelete == false)
                            .Where(x => productIds.Contains(x.ItemId))
                            .Include(t => t.Brand)
                            .Include(t => t.TblItemImages)
                            .ToListAsync();

                        // Update item quantities based on cart data
                        foreach (var item in tblItems)
                        {
                            var cartItem = listCartModel.Carts.FirstOrDefault(c => c.ProductId == item.ItemId);
                            if (cartItem != null)
                            {
                                item.Quantity = cartItem.Quantity;
                            }
                        }
                    }
                }

                // Create and populate the view model
                var viewModel = new CheckoutViewModel
                {
                    TblOrdersMain = new TblOrdersMain(),
                    TblItems = tblItems
                };

                // Populate view data for dropdowns
                ViewData["UserId"] = new SelectList(await _context.TblUsers.ToListAsync(), "UserId", "UserName");
                ViewData["CityId"] = new SelectList(await _context.TblCities.ToListAsync(), "CityId", "CityName");
                ViewData["CountryId"] = new SelectList(await _context.TblCountries.ToListAsync(), "CountryId", "CountryName");
                ViewData["ProvinceId"] = new SelectList(await _context.TblProvinces.ToListAsync(), "ProvinceId", "ProvinceName");
                ViewData["StatusId"] = new SelectList(await _context.TblStatuses.ToListAsync(), "StatusId", "StatusName");

                // If the user is authenticated, populate their details
                if (User.Identity.IsAuthenticated)
                {
                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    // Check if userId is not null or empty and try to parse it as int
                    if (int.TryParse(userId, out int parsedUserId))
                    {
                        var user = await _context.TblUsers.FindAsync(parsedUserId);

                        if (user != null)
                        {
                            viewModel.TblOrdersMain.UserId = user.UserId;
                            viewModel.TblOrdersMain.Email = user.Email;
                            viewModel.TblOrdersMain.PhoneNo = user.PhoneNumber;
                        }
                    }
                }

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Checkout");
                ViewBag.Message = ex.Message;
                return View(new CheckoutViewModel()); // Return an empty model in case of error
            }
        }

        [HttpPost("Checkout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Checkout([Bind("UserId,UserName,GrandTotal,OrderDate,Email,PhoneNo,CountryId,ProvinceId,CityId,PostalCode,DeliveryAddress,PaymentId,PaidAmount,PaymentType,Remarks,ShippingAmount,StatusId")] TblOrdersMain tblOrdersMain)
        {
            try
            {
                List<TblItem> tblItems = new List<TblItem>();

                if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
                {
                    var data = HttpContext.Request.Cookies["AutoHubCart"];
                    var DecryptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecryptData);

                    if (listCartModel != null && listCartModel.Carts.Count > 0)
                    {
                        List<int> ProductIds = listCartModel.Carts.Select(x => x.ProductId).ToList();

                        tblItems = await _context.TblItems
                            .Where(x => !x.MDelete || x.MDelete == null)
                            .Where(x => ProductIds.Contains(x.ItemId))
                            .Include(t => t.Brand)
                            .Include(t => t.TblItemImages)
                            .ToListAsync();

                        foreach (var item in tblItems)
                        {
                            var cartItem = listCartModel.Carts.FirstOrDefault(c => c.ProductId == item.ItemId);
                            if (cartItem != null)
                            {
                                item.Quantity = cartItem.Quantity;
                            }
                        }

                       
                    }
                }


                if (User.Identity.IsAuthenticated)
                {
                    var userIdString = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                    decimal grandTotal = 0;
                    foreach (var item in tblItems)
                    {
                        grandTotal += item.ItemPrice * item.Quantity;

                    }
                    decimal paidAmount = grandTotal + 500;

                    if (int.TryParse(userIdString, out int userId))
                    {
                    

                        tblOrdersMain.UserId = userId;
                        tblOrdersMain.OrderDate = DateTime.Today;
                        tblOrdersMain.StatusId = 1;
                        tblOrdersMain.ShippingAmount = 500;
                        tblOrdersMain.GrandTotal = grandTotal;
                        tblOrdersMain.PaymentId = 1;
                        tblOrdersMain.PaidAmount = paidAmount;
                        tblOrdersMain.CreatedAt = DateTime.Today;
                        tblOrdersMain.Createdby = userId;
                        tblOrdersMain.DiscountAmount = 0;
                        tblOrdersMain.DeliverDays = DateTime.Today.AddDays(3);

                        _context.TblOrdersMains.Add(tblOrdersMain);
                        await _context.SaveChangesAsync();
                        foreach (var item in tblItems)
                        {
                            var orderDetail = new TblOrderDetail
                            {
                                ItemId = item.ItemId,
                                ItemAmount = item.ItemPrice,
                                ItemQuantity = item.Quantity,
                                TotelAmount = item.ItemPrice * item.Quantity,
                                DiscountAmount = item.Discount ?? 0,
                                CreatedAt = DateTime.Today,
                                CreatedBy = userId,
                                MDelete = false,
                                OrderMainId = tblOrdersMain.OrderId 
                            };

                            _context.TblOrderDetails.Add(orderDetail);
                        }
                        await _context.SaveChangesAsync();

                        return RedirectToAction("ConfirmOrder", "Home", new { id = tblOrdersMain.OrderId });
                    }
                }


                else
                {
                    // Handle new user registration
                    var existingUser = await _context.TblUsers.FirstOrDefaultAsync(x => x.Email == tblOrdersMain.Email);
                    var roll = "";
                    if(existingUser.RollId == 1)
                    {
                        roll = "Admin";
                    }
                    else
                    {
                        roll = "Customer";
                    }
                    if (existingUser == null)
                    {
                        var newUser = new TblUser
                        {


                            UserName = "New User", // Default name or change based on the form input
                            Email = tblOrdersMain.Email,
                            Password = GeneratePassword.GenerateRandomPassword(10),
                            PhoneNumber = tblOrdersMain.PhoneNo,
                            RollId = 2 // Role for non-admin users
                        };

                        _context.TblUsers.Add(newUser);
                        await _context.SaveChangesAsync();

                        // Send welcome email
                        var receiver = tblOrdersMain.Email;
                        var subject = "Welcome to AutoPartsHub";
                        var message = $"Your Login Password is {newUser.Password} and your ID is {newUser.UserId}";

                        if (!IsValidEmail(receiver))
                        {
                            return Json(new { success = false, error = "Invalid email address" });
                        }

                        try
                        {
                            await _mailService.SendMailAsync(receiver, subject, message);

                            // Sign in the new user
                            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, newUser.UserName),
                        new Claim(ClaimTypes.Email, newUser.Email),
                        new Claim(ClaimTypes.Role, "Customer"),
                        new Claim("RoleId", newUser.RollId.ToString())
                    };

                            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
							decimal grandTotal = 0;
							foreach (var item in tblItems)
							{
								grandTotal += item.ItemPrice * item.Quantity;

							}
							decimal paidAmount = grandTotal + 500;



							tblOrdersMain.UserId = newUser.UserId;
                                tblOrdersMain.OrderDate = DateTime.Today;
                                tblOrdersMain.StatusId = 1;
                                tblOrdersMain.ShippingAmount = 500;
                                tblOrdersMain.GrandTotal = grandTotal;
                                tblOrdersMain.PaymentId = 1;
                            tblOrdersMain.CreatedAt = DateTime.Today;
							tblOrdersMain.Createdby = newUser.UserId;
							tblOrdersMain.PaidAmount = paidAmount;
                                tblOrdersMain.DiscountAmount = 0;
                                tblOrdersMain.DeliverDays = DateTime.Today.AddDays(3);


                                _context.TblOrdersMains.Add(tblOrdersMain);
                                await _context.SaveChangesAsync();

                                foreach (var item in tblItems)
                                {
                                    var orderDetail = new TblOrderDetail
                                    {
                                        ItemId = item.ItemId,
                                        ItemAmount = item.ItemPrice,
                                        ItemQuantity = item.Quantity ,
                                        TotelAmount = item.ItemPrice * item.Quantity ,
                                        DiscountAmount = item.Discount ?? 0,
                                        CreatedAt = DateTime.Today,
                                        CreatedBy = newUser.UserId,
                                        MDelete = false,
                                        OrderMainId = tblOrdersMain.OrderId
                                    };

                                    _context.TblOrderDetails.Add(orderDetail);
                                }
                                await _context.SaveChangesAsync();

                                return RedirectToAction("ConfirmOrder", "Home", new { id = tblOrdersMain.OrderId });
                           
                        }
                        catch (Exception ex)
                        {
                            // Log and handle email sending failure
                            _logger.LogError(ex, "Error sending email");
                            return Json(new { success = false, error = "Failed to send email" });
                        }
                    }
                    else
                    {
                        // Existing user logic
                   
						var claims = new List<Claim>
		{
			new Claim(ClaimTypes.NameIdentifier, existingUser.UserId.ToString()),
			new Claim(ClaimTypes.Name, existingUser.UserName),
			new Claim(ClaimTypes.Email, existingUser.Email),
      new Claim(ClaimTypes.Role, roll),
            new Claim("RoleId", existingUser.RollId.ToString()),
		};

						var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

						decimal grandTotal = 0;
						foreach (var item in tblItems)
						{
							grandTotal += item.ItemPrice * item.Quantity;

						}
						decimal paidAmount = grandTotal + 500;

						tblOrdersMain.UserId = existingUser.UserId;
                            tblOrdersMain.OrderDate = DateTime.Today;
                            tblOrdersMain.StatusId = 1;
                            tblOrdersMain.ShippingAmount = 500;
                            tblOrdersMain.GrandTotal = grandTotal;
                            tblOrdersMain.PaymentId = 1;
						tblOrdersMain.CreatedAt = DateTime.Today;
						tblOrdersMain.Createdby = existingUser.UserId;
						tblOrdersMain.PaidAmount = paidAmount;
                            tblOrdersMain.DiscountAmount = 0;
                            tblOrdersMain.DeliverDays = DateTime.Today.AddDays(3);


                            _context.TblOrdersMains.Add(tblOrdersMain);
                            await _context.SaveChangesAsync();

                            foreach (var item in tblItems)
                            {
                                var orderDetail = new TblOrderDetail
                                {
                                    ItemId = item.ItemId,
                                    ItemAmount = item.ItemPrice,
                                    ItemQuantity = item.Quantity ,
                                    TotelAmount = item.ItemPrice * item.Quantity ,
                                    DiscountAmount = item.Discount ?? 0,
                                    CreatedAt = DateTime.Now,
                                    CreatedBy = existingUser.UserId,
                                    MDelete = false,
                                    OrderMainId = tblOrdersMain.OrderId
                                };

                                _context.TblOrderDetails.Add(orderDetail);
                            }
                            await _context.SaveChangesAsync();

                            return RedirectToAction("ConfirmOrder", "Home", new { id = tblOrdersMain.OrderId });
                        
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing checkout");
                ViewBag.Message = ex.Message;

                //var viewModel = await PopulateCheckoutViewModelAsync(tblOrdersMain);
                ViewData["UserId"] = new SelectList(await _context.TblUsers.ToListAsync(), "UserId", "UserName");
                ViewData["CityId"] = new SelectList(await _context.TblCities.ToListAsync(), "CityId", "CityName");
                ViewData["CountryId"] = new SelectList(await _context.TblCountries.ToListAsync(), "CountryId", "CountryName");
                ViewData["ProvinceId"] = new SelectList(await _context.TblProvinces.ToListAsync(), "ProvinceId", "ProvinceName");
                ViewData["StatusId"] = new SelectList(await _context.TblStatuses.ToListAsync(), "StatusId", "StatusName");

                return View();
            }

            // Ensure there is a return statement for all code paths
            return View();
        }



        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        [Route("wishList")]
        [HttpGet]
        public async Task<IActionResult> WishList()
        {

            List<TblItem> tblItems = new List<TblItem>();

            if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubWishList"]))
            {
                var data = HttpContext.Request.Cookies["AutoHubWishList"];
                var DecriptData = Protection.Decrypt(data);

                ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                if (listCartModel != null && listCartModel.Carts.Count > 0)
                {
                    List<int> ProductIds = listCartModel.Carts.Select(x => x.ProductId).ToList();

                    tblItems = (await _context.TblItems
                                      .Where(x => x.MDelete == false || x.MDelete == null)
                                      .Where(x => ProductIds.Contains(x.ItemId))
                                      .Include(t => t.Brand).Include(t => t.TblItemImages)
                                      .ToListAsync());

                    foreach (var item in tblItems)
                    {
                        var cartItem = listCartModel.Carts.FirstOrDefault(c => c.ProductId == item.ItemId);
                        if (cartItem != null)
                        {
                            item.Quantity = cartItem.Quantity;
                        }
                    }


                }
                else
                {

                }
            }



            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");

            return View(tblItems);

        }


        [Route("/addToWishList")]
        [HttpPost]
        public IActionResult WishList(int itemId, int quantity)
        {

            try
            {
                CookieOptions cookieOptions = new CookieOptions();
                cookieOptions.Secure = true;
                cookieOptions.HttpOnly = true;
                cookieOptions.Expires = DateTime.Now.AddDays(30);
                cookieOptions.IsEssential = true;

                if (string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubWishList"]))
                {
                    CartModel cartModel = new CartModel()
                    {
                        ProductId = itemId,
                        Quantity = quantity
                    };

                    ListCartModel listCartModel = new ListCartModel();
                    listCartModel.Carts.Add(cartModel);

                    string JsonData = JsonConvert.SerializeObject(listCartModel);

                    var ProtectedData = Protection.Encrypt(JsonData);

                    HttpContext.Response.Cookies.Append("AutoHubWishList", ProtectedData, cookieOptions);
                }
                else
                {
                    var data = HttpContext.Request.Cookies["AutoHubWishList"];

                    var DecriptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                    if (listCartModel != null && listCartModel.Carts.Count > 0)
                    {
                        if (listCartModel.Carts.Any(x => x.ProductId == itemId))
                        {
                            return Json(new { success = false, message = "Item  Already in the Wish List" });

                        }
                        else
                        {
                            listCartModel.Carts.Add(new CartModel()
                            {
                                ProductId = itemId,
                                Quantity = quantity
                            });


                            string JsonData = JsonConvert.SerializeObject(listCartModel);

                            var ProtectedData = Protection.Encrypt(JsonData);

                            HttpContext.Response.Cookies.Append("AutoHubWishList", ProtectedData, cookieOptions);

                        }
                    }
                    else
                    {
                        CookieOptions cookieOptionsNew = new CookieOptions();
                        cookieOptionsNew.Secure = true;
                        cookieOptionsNew.HttpOnly = true;
                        cookieOptionsNew.Expires = DateTime.Now.AddDays(-1);
                        HttpContext.Response.Cookies.Append("AutoHubWishList", "", cookieOptionsNew);
                        HttpContext.Response.Cookies.Delete("AutoHubWishList");
                        throw new Exception("Some things went wrong");

                    }

                }

                return Json(new { success = true, message = "Item added to WishList successfully" });
            }
            catch (Exception exp)
            {

                return Json(new { success = false, message = exp.Message });

            }
        }



        [Route("addToCart")]
        [HttpPost]
        public IActionResult AddToCart(int itemId, int quantity)
        {

            try
            {
                CookieOptions cookieOptions = new CookieOptions();
                cookieOptions.Secure = true;
                cookieOptions.HttpOnly = true;
                cookieOptions.Expires = DateTime.Now.AddDays(30);
                cookieOptions.IsEssential = true;

                if (string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
                {
                    CartModel cartModel = new CartModel()
                    {
                        ProductId = itemId,
                        Quantity = quantity
                    };

                    ListCartModel listCartModel = new ListCartModel();
                    listCartModel.Carts.Add(cartModel);

                    string JsonData = JsonConvert.SerializeObject(listCartModel);

                    var ProtectedData = Protection.Encrypt(JsonData);

                    HttpContext.Response.Cookies.Append("AutoHubCart", ProtectedData, cookieOptions);
                }
                else
                {
                    var data = HttpContext.Request.Cookies["AutoHubCart"];

                    var DecriptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                    if (listCartModel != null && listCartModel.Carts.Count > 0)
                    {
                        if (listCartModel.Carts.Any(x => x.ProductId == itemId))
                        {
                            return Json(new { success = true, message = "Item  Already in the cart" });

                        }
                        else
                        {
                            listCartModel.Carts.Add(new CartModel()
                            {
                                ProductId = itemId,
                                Quantity = quantity
                            });


                            string JsonData = JsonConvert.SerializeObject(listCartModel);

                            var ProtectedData = Protection.Encrypt(JsonData);

                            HttpContext.Response.Cookies.Append("AutoHubCart", ProtectedData, cookieOptions);

                        }
                    }
                    else
                    {
                        CookieOptions cookieOptionsNew = new CookieOptions();
                        cookieOptionsNew.Secure = true;
                        cookieOptionsNew.HttpOnly = true;
                        cookieOptionsNew.Expires = DateTime.Now.AddDays(-1);
                        HttpContext.Response.Cookies.Append("AutoHubCart", "", cookieOptionsNew);
                        HttpContext.Response.Cookies.Delete("AutoHubCart");
                        throw new Exception("Some things went wrong");

                    }

                }

                return Json(new { success = true, message = "Item added to cart successfully" });
            }
            catch (Exception exp)
            {

                return Json(new { success = false, message = exp.Message });

            }



        }





        // POST: Items/Delete/5
        [HttpPost, ActionName("DeleteFromCart")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteFromCart(int id)
        {
            try
            {
                if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubCart"]))
                {
                    var data = HttpContext.Request.Cookies["AutoHubCart"];
                    var DecriptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                    var cartData = listCartModel.Carts.FirstOrDefault(x => x.ProductId == id);

                    listCartModel.Carts.Remove(cartData);

                    CookieOptions cookieOptions = new CookieOptions();
                    cookieOptions.Secure = true;
                    cookieOptions.HttpOnly = true;
                    cookieOptions.Expires = DateTime.Now.AddDays(30);
                    cookieOptions.IsEssential = true;


                    string JsonData = JsonConvert.SerializeObject(listCartModel);

                    var ProtectedData = Protection.Encrypt(JsonData);

                    HttpContext.Response.Cookies.Append("AutoHubCart", ProtectedData, cookieOptions);


                }

                ViewBag.SuccessMsg = "Item Removed Successfully";

                return RedirectToAction(nameof(Cart));
            }
            catch (Exception exp)
            {
                ViewBag.ErrorMsg = exp.Message;
                return RedirectToAction(nameof(Cart));
            }


        }
        // POST: Items/Delete/5
        [HttpPost, ActionName("DeleteFromWishList")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteFromWishList(int id)
        {
            try
            {
                if (!string.IsNullOrEmpty(HttpContext.Request.Cookies["AutoHubWishList"]))
                {
                    var data = HttpContext.Request.Cookies["AutoHubWishList"];
                    var DecriptData = Protection.Decrypt(data);

                    ListCartModel listCartModel = JsonConvert.DeserializeObject<ListCartModel>(DecriptData);

                    var cartData = listCartModel.Carts.FirstOrDefault(x => x.ProductId == id);

                    listCartModel.Carts.Remove(cartData);

                    CookieOptions cookieOptions = new CookieOptions();
                    cookieOptions.Secure = true;
                    cookieOptions.HttpOnly = true;
                    cookieOptions.Expires = DateTime.Now.AddDays(30);
                    cookieOptions.IsEssential = true;


                    string JsonData = JsonConvert.SerializeObject(listCartModel);

                    var ProtectedData = Protection.Encrypt(JsonData);

                    HttpContext.Response.Cookies.Append("AutoHubWishList", ProtectedData, cookieOptions);


                }

                ViewBag.SuccessMsg = "Item Removed Successfully";

                return RedirectToAction(nameof(WishList));
            }
            catch (Exception exp)
            {
                ViewBag.ErrorMsg = exp.Message;
                return RedirectToAction(nameof(WishList));
            }

        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
