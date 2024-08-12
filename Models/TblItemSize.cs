using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblItemSize
{
    public int ItemSizeId { get; set; }

    public int? SizeId { get; set; }

    public int? ItemId { get; set; }

    public decimal? SizePrice { get; set; }

    public Boolean IsDefault { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool? MDelete { get; set; }

    public virtual TblItem? Item { get; set; }

    public virtual TblSize? Size { get; set; }
}
