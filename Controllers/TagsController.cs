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
    public class TagsController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public TagsController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: Tags
        public async Task<IActionResult> Index()

        {
            var brnds = await _context.TblTags.Where(x => x.MDelete == false || x.MDelete == null).ToListAsync();
            return View(brnds);
        }

        // GET: Tags/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblTag = await _context.TblTags
                .FirstOrDefaultAsync(m => m.TagId == id);
            if (tblTag == null)
            {
                return NotFound();
            }

            return View(tblTag);
        }

        // GET: Tags/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Tags/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("TagId,TagName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblTag tblTag)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblTag);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblTag);
        }

        // GET: Tags/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblTag = await _context.TblTags.FindAsync(id);
            if (tblTag == null)
            {
                return NotFound();
            }
            return View(tblTag);
        }

        // POST: Tags/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("TagId,TagName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblTag tblTag)
        {
            if (id != tblTag.TagId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblTag);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblTagExists(tblTag.TagId))
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
            return View(tblTag);
        }

        // GET: Tags/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblTag = await _context.TblTags
                .FirstOrDefaultAsync(m => m.TagId == id);
            if (tblTag == null)
            {
                return NotFound();
            }

            return View(tblTag);
        }

        // POST: Tags/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblTag = await _context.TblTags.FindAsync(id);
            if (tblTag != null)
            {

                tblTag.MDelete = true;
                _context.TblTags.Update(tblTag);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblTagExists(int id)
        {
            return _context.TblTags.Any(e => e.TagId == id);
        }
    }
}
