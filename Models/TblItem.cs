using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;

namespace AutoPartsHub.Models;

public partial class TblItem
{
    public int ItemId { get; set; }

    public string? ItemSlugs { get; set; }

    public string ItemName { get; set; } = null!;

    public decimal ItemPrice { get; set; }

    public decimal? Discount { get; set; }

    public Boolean IsFeature { get; set; }

    public int? BrandId { get; set; }

    public string? Sku { get; set; }

    public string? DefaultImageUrl { get; set; }
    [NotMapped]
    public IFormFile? DefaultImageFile { get; set; }

    [NotMapped]
    public int Quantity { get; set; }

    public string? ShortDescription { get; set; }

    public string? LongDescription { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual TblBrand? Brand { get; set; }

    public virtual ICollection<TblItemCategory> TblItemCategories { get; set; } = new List<TblItemCategory>();
    public virtual ICollection<TblItemReview> TblItemReviews { get; set; } = new List<TblItemReview>();

    public virtual ICollection<TblItemColor> TblItemColors { get; set; } = new List<TblItemColor>();

    public virtual ICollection<TblItemImage> TblItemImages { get; set; } = new List<TblItemImage>();

    public virtual ICollection<TblItemSize> TblItemSizes { get; set; } = new List<TblItemSize>();

    public virtual ICollection<TblItemTag> TblItemTags { get; set; } = new List<TblItemTag>();

    public virtual ICollection<TblOrderDetail> TblOrderDetails { get; set; } = new List<TblOrderDetail>();

    [NotMapped]
    public decimal TotalPrice
    {
        get
        {
            return Convert.ToDecimal(ItemPrice * Quantity);
        }
    }

    public static implicit operator TblItem(List<TblItem> v)
    {
        throw new NotImplementedException();
    }
}
