using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblOrderDetail
{
    public int OrderDetailId { get; set; }

    public int? ItemId { get; set; }

    public decimal ItemAmount { get; set; }

    public int ItemQuantity { get; set; }

    public decimal TotelAmount { get; set; }

    public decimal? DiscountAmount { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public int? OrderMainId { get; set; }

    public virtual TblItem? Item { get; set; }

    public virtual TblOrdersMain? OrderMain { get; set; }
}
