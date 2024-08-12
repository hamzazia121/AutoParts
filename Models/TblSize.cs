using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblSize
{
    public int SizeId { get; set; }

    public string SizeName { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblItemSize> TblItemSizes { get; set; } = new List<TblItemSize>();
}
