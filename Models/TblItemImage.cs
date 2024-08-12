using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblItemImage
{
    public int ItemImageId { get; set; }

    public string? ItemImageName { get; set; }

    public string? ThumbnailImage { get; set; }

    public string? NormalImage { get; set; }

    public bool IsDefault { get; set; }=false;

    public int ItemId { get; set; } = 0;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }
    
    public string? BanerImage { get; set; }

    public virtual TblItem? Item { get; set; }
}

class ImagesType
{
    public string Default { get; set; } = string.Empty;
    public string Slider { get; set; } = string.Empty;
    public string Thumbnail { get; set; } = string.Empty;
}
