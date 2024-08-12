using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblItemCategory
{
    public int ItemCategoryId { get; set; }

    public int CategoryId { get; set; }

    public int ItemId { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual TblCategory Category { get; set; } = null!;

    public virtual TblItem Item { get; set; } = null!;
}
