using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;
using Microsoft.AspNetCore.Authorization;

namespace AutoPartsHub.Controllers
{

    [CustomAuthorization]
    [Authorize(Roles = "Admin")]
    public class ShippingPoliciesController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ShippingPoliciesController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: ShippingPolicies
        public async Task<IActionResult> Index()
        {
            var ShippingPolicies = await _context.TblShippingPolicies.Where(x => x.MDelete == false || x.MDelete == null).ToListAsync();
            return View(ShippingPolicies);
        }

        // GET: ShippingPolicies/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblShippingPolicy = await _context.TblShippingPolicies
                .FirstOrDefaultAsync(m => m.ShipingId == id);
            if (tblShippingPolicy == null)
            {
                return NotFound();
            }

            return View(tblShippingPolicy);
        }

        // GET: ShippingPolicies/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: ShippingPolicies/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ShipingId,PolicyAmount,IsLifeTime,PolicyStatsDate,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblShippingPolicy tblShippingPolicy)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblShippingPolicy);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblShippingPolicy);
        }

        // GET: ShippingPolicies/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblShippingPolicy = await _context.TblShippingPolicies.FindAsync(id);
            if (tblShippingPolicy == null)
            {
                return NotFound();
            }
            return View(tblShippingPolicy);
        }

        // POST: ShippingPolicies/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ShipingId,PolicyAmount,IsLifeTime,PolicyStatsDate,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblShippingPolicy tblShippingPolicy)
        {
            if (id != tblShippingPolicy.ShipingId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblShippingPolicy);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblShippingPolicyExists(tblShippingPolicy.ShipingId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(tblShippingPolicy);
        }

        // GET: ShippingPolicies/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblShippingPolicy = await _context.TblShippingPolicies
                .FirstOrDefaultAsync(m => m.ShipingId == id);
            if (tblShippingPolicy == null)
            {
                return NotFound();
            }

            return View(tblShippingPolicy);
        }

        // POST: ShippingPolicies/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblShippingPolicy = await _context.TblShippingPolicies.FindAsync(id);
            if (tblShippingPolicy != null)
            {
                tblShippingPolicy.MDelete = true;
                _context.TblShippingPolicies.Update(tblShippingPolicy);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblShippingPolicyExists(int id)
        {
            return _context.TblShippingPolicies.Any(e => e.ShipingId == id);
        }
    }
}
