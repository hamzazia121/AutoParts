using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace AutoPartsHub.Models
{
    public sealed class SoftDeleteInterceptor : SaveChangesInterceptor
    {
        private readonly IHttpContextAccessor _contextAccessor;

        public SoftDeleteInterceptor(IHttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
        }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            int userId = Convert.ToInt32(_contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier));

            if (eventData.Context is null)
            {
                return base.SavingChangesAsync(eventData, result, cancellationToken);
            }

            IEnumerable<EntityEntry<ISoftDeleteTable>> entries =
                eventData
                    .Context
                    .ChangeTracker
                    .Entries<ISoftDeleteTable>()
                    .Where(e => e.State == EntityState.Deleted);

            foreach (EntityEntry<ISoftDeleteTable> softDeletable in entries)
            {
                softDeletable.State = EntityState.Modified;
                softDeletable.Entity.MDelete = true;
                softDeletable.Entity.UpdatedAt = DateTime.Now;
                softDeletable.Entity.UpdatedBy = userId;
            }

            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }
}
