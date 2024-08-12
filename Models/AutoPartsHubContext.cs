using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace AutoPartsHub.Models;

public partial class AutoPartsHubContext : DbContext
{
    public AutoPartsHubContext()
    {
    }

    public AutoPartsHubContext(DbContextOptions<AutoPartsHubContext> options)
        : base(options)
    {
    }

    public virtual DbSet<TblBrand> TblBrands { get; set; }

    public virtual DbSet<TblCategory> TblCategories { get; set; }

    public virtual DbSet<TblCity> TblCities { get; set; }

    public virtual DbSet<TblColor> TblColors { get; set; }

    public virtual DbSet<TblContactU> TblContactUs { get; set; }

    public virtual DbSet<TblCountry> TblCountries { get; set; }

    public virtual DbSet<TblItem> TblItems { get; set; }

    public virtual DbSet<TblItemCategory> TblItemCategories { get; set; }

    public virtual DbSet<TblItemColor> TblItemColors { get; set; }

    public virtual DbSet<TblItemImage> TblItemImages { get; set; }

    public virtual DbSet<TblItemReview> TblItemReviews { get; set; }

    public virtual DbSet<TblItemSize> TblItemSizes { get; set; }

    public virtual DbSet<TblItemTag> TblItemTags { get; set; }

    public virtual DbSet<TblNewsLater> TblNewsLaters { get; set; }

    public virtual DbSet<TblOrderDetail> TblOrderDetails { get; set; }

    public virtual DbSet<TblOrdersMain> TblOrdersMains { get; set; }

    public virtual DbSet<TblPayment> TblPayments { get; set; }

    public virtual DbSet<TblPaymentLog> TblPaymentLogs { get; set; }

    public virtual DbSet<TblProvince> TblProvinces { get; set; }

    public virtual DbSet<TblRoll> TblRolls { get; set; }

    public virtual DbSet<TblShippingPolicy> TblShippingPolicies { get; set; }

    public virtual DbSet<TblSize> TblSizes { get; set; }

    public virtual DbSet<TblStatus> TblStatuses { get; set; }

    public virtual DbSet<TblTag> TblTags { get; set; }

    public virtual DbSet<TblUser> TblUsers { get; set; }

    public virtual DbSet<TblVoucherCode> TblVoucherCodes { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseSqlServer("Server=localhost;database=AutoPartsHub;Trusted_Connection=True;TrustServerCertificate=True;");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TblBrand>(entity =>
        {
            entity.HasKey(e => e.BrandId);

            entity.ToTable("tbl_Brand");

            entity.Property(e => e.BrandId).HasColumnName("BrandID");
            entity.Property(e => e.BrandDescription).HasMaxLength(1000);
            entity.Property(e => e.BrandImage).HasMaxLength(500);
            entity.Property(e => e.BrandName).HasMaxLength(250);
            entity.Property(e => e.BrandShortName).HasMaxLength(50);
            entity.Property(e => e.BrandTitle).HasMaxLength(250);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
        });

        modelBuilder.Entity<TblCategory>(entity =>
        {
            entity.HasKey(e => e.CategoryId);

            entity.ToTable("tbl_Category");

            entity.Property(e => e.CategoryId).HasColumnName("CategoryID");
            entity.Property(e => e.CategoryDescription).HasMaxLength(1000);
            entity.Property(e => e.CategoryImage).HasMaxLength(500);
            entity.Property(e => e.CategoryName).HasMaxLength(250);
            entity.Property(e => e.CategoryTitle).HasMaxLength(250);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
        });

        modelBuilder.Entity<TblCity>(entity =>
        {
            entity.HasKey(e => e.CityId);

            entity.ToTable("tbl_City");

            entity.Property(e => e.CityId).HasColumnName("CityID");
            entity.Property(e => e.CityName).HasMaxLength(250);
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
        });

        modelBuilder.Entity<TblColor>(entity =>
        {
            entity.HasKey(e => e.ColorId);

            entity.ToTable("tbl_Color");

            entity.Property(e => e.ColorId).HasColumnName("ColorID");
            entity.Property(e => e.ColorName)
                .HasMaxLength(250)
                .HasColumnName("colorName");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
        });

        modelBuilder.Entity<TblContactU>(entity =>
        {
            entity.HasKey(e => e.ContectUsId).HasName("PK_tbl_ContectUs");

            entity.ToTable("tbl_ContactUs");

            entity.Property(e => e.ContectUsId).HasColumnName("ContectUsID");
            entity.Property(e => e.ContectUsEmail).HasMaxLength(50);
            entity.Property(e => e.ContectUsMassage).HasMaxLength(200);
            entity.Property(e => e.ContectUsName).HasMaxLength(50);
            entity.Property(e => e.ContectUsPhoneNo).HasMaxLength(20);
            entity.Property(e => e.ContectUsSubject).HasMaxLength(50);
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
        });

        modelBuilder.Entity<TblCountry>(entity =>
        {
            entity.HasKey(e => e.CountryId);

            entity.ToTable("tbl_Country");

            entity.Property(e => e.CountryId).HasColumnName("CountryID");
            entity.Property(e => e.CountryName).HasMaxLength(50);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
        });

        modelBuilder.Entity<TblItem>(entity =>
        {
            entity.HasKey(e => e.ItemId);

            entity.ToTable("tbl_Items");

            entity.Property(e => e.ItemId).HasColumnName("ItemID");
            entity.Property(e => e.BrandId).HasColumnName("BrandID");
            entity.Property(e => e.DefaultImageUrl)
                .HasMaxLength(250)
                .HasColumnName("DefaultImageURL");
            entity.Property(e => e.Discount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.ItemName).HasMaxLength(50);
            entity.Property(e => e.ItemPrice).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.ItemSlugs).HasMaxLength(250);
            entity.Property(e => e.LongDescription).HasColumnType("text");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.ShortDescription).HasMaxLength(1500);
            entity.Property(e => e.Sku)
                .HasMaxLength(50)
                .HasColumnName("SKU");

            entity.HasOne(d => d.Brand).WithMany(p => p.TblItems)
                .HasForeignKey(d => d.BrandId)
                .HasConstraintName("FK_tbl_Items_tbl_Brand");
        });

        modelBuilder.Entity<TblItemCategory>(entity =>
        {
            entity.HasKey(e => e.ItemCategoryId).HasName("PK_tbl_ProductCategory");

            entity.ToTable("tbl_ItemCategory");

            entity.Property(e => e.ItemCategoryId).HasColumnName("ItemCategoryID");
            entity.Property(e => e.CategoryId).HasColumnName("CategoryID");
            entity.Property(e => e.CreatedBy).HasColumnName("createdBy");
            entity.Property(e => e.ItemId).HasColumnName("ItemID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");

            entity.HasOne(d => d.Category).WithMany(p => p.TblItemCategories)
                .HasForeignKey(d => d.CategoryId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_tbl_ItemCategory_tbl_Category");

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemCategories)
                .HasForeignKey(d => d.ItemId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_tbl_ItemCategory_tbl_Items");
        });

        modelBuilder.Entity<TblItemColor>(entity =>
        {
            entity.HasKey(e => e.ItemColorId);

            entity.ToTable("tbl_Item_Color");

            entity.Property(e => e.ColorPrice).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.IsDefault).HasColumnName("isDefault");
            entity.Property(e => e.MDelete)
                .HasDefaultValue(false)
                .HasColumnName("mDelete");

            entity.HasOne(d => d.Color).WithMany(p => p.TblItemColors)
                .HasForeignKey(d => d.ColorId)
                .HasConstraintName("FK_tbl_Item_Color_tbl_Color");

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemColors)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_Item_Color_tbl_Items");
        });

        modelBuilder.Entity<TblItemImage>(entity =>
        {
            entity.HasKey(e => e.ItemImageId);

            entity.ToTable("tbl_ItemImages");

            entity.Property(e => e.ItemImageId).HasColumnName("ItemImageID");
            entity.Property(e => e.BanerImage).HasMaxLength(500);
            entity.Property(e => e.ItemId).HasColumnName("ItemID");
            entity.Property(e => e.ItemImageName).HasMaxLength(50);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.NormalImage).HasMaxLength(700);
            entity.Property(e => e.ThumbnailImage).HasMaxLength(1000);

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemImages)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_ItemImages_tbl_Items");
        });

        modelBuilder.Entity<TblItemReview>(entity =>
        {
            entity.HasKey(e => e.ReviewId);

            entity.ToTable("tbl_ItemReview");

            entity.Property(e => e.ReviewId).HasColumnName("ReviewID");
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
            entity.Property(e => e.ReviewName).HasMaxLength(50);
            entity.Property(e => e.ReviewText).HasMaxLength(500);

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemReviews)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_ItemReview_tbl_Items");
        });

        modelBuilder.Entity<TblItemSize>(entity =>
        {
            entity.HasKey(e => e.ItemSizeId).HasName("PK_tbl_Item_Size_1");

            entity.ToTable("tbl_Item_Size");

            entity.Property(e => e.IsDefault).HasColumnName("isDefault");
            entity.Property(e => e.MDelete)
                .HasDefaultValue(false)
                .HasColumnName("mDelete");
            entity.Property(e => e.SizePrice).HasColumnType("decimal(18, 2)");

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemSizes)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_Item_Size_tbl_Items");

            entity.HasOne(d => d.Size).WithMany(p => p.TblItemSizes)
                .HasForeignKey(d => d.SizeId)
                .HasConstraintName("FK_tbl_Item_Size_tbl_Size");
        });

        modelBuilder.Entity<TblItemTag>(entity =>
        {
            entity.HasKey(e => e.ItemTagId);

            entity.ToTable("tbl_ItemTags");

            entity.Property(e => e.ItemTagId).HasColumnName("ItemTagID");
            entity.Property(e => e.ItemId).HasColumnName("ItemID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.TagId).HasColumnName("TagID");

            entity.HasOne(d => d.Item).WithMany(p => p.TblItemTags)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_ItemTags_tbl_Items");

            entity.HasOne(d => d.Tag).WithMany(p => p.TblItemTags)
                .HasForeignKey(d => d.TagId)
                .HasConstraintName("FK_tbl_ItemTags_tbl_Tags");
        });

        modelBuilder.Entity<TblNewsLater>(entity =>
        {
            entity.HasKey(e => e.NewsLaterId);

            entity.ToTable("tbl_NewsLater");

            entity.Property(e => e.NewsLaterId).HasColumnName("NewsLaterID");
            entity.Property(e => e.EmailAddress).HasMaxLength(50);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
        });

        modelBuilder.Entity<TblOrderDetail>(entity =>
        {
            entity.HasKey(e => e.OrderDetailId);

            entity.ToTable("tbl_OrderDetails");

            entity.Property(e => e.OrderDetailId).HasColumnName("OrderDetailID");
            entity.Property(e => e.DiscountAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.ItemAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.ItemId).HasColumnName("ItemID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.TotelAmount).HasColumnType("decimal(18, 2)");

            entity.HasOne(d => d.Item).WithMany(p => p.TblOrderDetails)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("FK_tbl_OrderDetails_tbl_Items");

            entity.HasOne(d => d.OrderMain).WithMany(p => p.TblOrderDetails)
                .HasForeignKey(d => d.OrderMainId)
                .HasConstraintName("FK_tbl_OrderDetails_tbl_OrdersMain");
        });

        modelBuilder.Entity<TblOrdersMain>(entity =>
        {
            entity.HasKey(e => e.OrderId);

            entity.ToTable("tbl_OrdersMain");

            entity.Property(e => e.CityId).HasColumnName("CityID");
            entity.Property(e => e.CountryId).HasColumnName("CountryID");
            entity.Property(e => e.DeliveryAddress).HasMaxLength(500);
            entity.Property(e => e.DiscountAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.Email).HasMaxLength(50);
            entity.Property(e => e.GrandTotal).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.PaidAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.PaymentId).HasColumnName("PaymentID");
            entity.Property(e => e.PaymentType).HasMaxLength(50);
            entity.Property(e => e.PhoneNo).HasMaxLength(50);
            entity.Property(e => e.PostelCode).HasMaxLength(20);
            entity.Property(e => e.ProvinceId).HasColumnName("ProvinceID");
            entity.Property(e => e.ShippingAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.StatusId).HasColumnName("StatusID");
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.City).WithMany(p => p.TblOrdersMains)
                .HasForeignKey(d => d.CityId)
                .HasConstraintName("FK_tbl_OrdersMain_tbl_City");

            entity.HasOne(d => d.Country).WithMany(p => p.TblOrdersMains)
                .HasForeignKey(d => d.CountryId)
                .HasConstraintName("FK_tbl_OrdersMain_tbl_Country");

            entity.HasOne(d => d.Province).WithMany(p => p.TblOrdersMains)
                .HasForeignKey(d => d.ProvinceId)
                .HasConstraintName("FK_tbl_OrdersMain_tbl_Province");

            entity.HasOne(d => d.Status).WithMany(p => p.TblOrdersMains)
                .HasForeignKey(d => d.StatusId)
                .HasConstraintName("FK_tbl_OrdersMain_tbl_Status");

            entity.HasOne(d => d.User).WithMany(p => p.TblOrdersMains)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_tbl_OrdersMain_tbl_User");
        });

        modelBuilder.Entity<TblPayment>(entity =>
        {
            entity.HasKey(e => e.PaymentId);

            entity.ToTable("tbl_Payment");

            entity.Property(e => e.PaymentId).HasColumnName("PaymentID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.PaymentAmount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.PaymentLogId).HasColumnName("PaymentLogID");
            entity.Property(e => e.PaymentStatus).HasMaxLength(50);
            entity.Property(e => e.PaymentTokenId).HasColumnName("PaymentTokenID");
            entity.Property(e => e.PaymentType).HasMaxLength(50);
            entity.Property(e => e.Url)
                .HasMaxLength(500)
                .HasColumnName("URL");
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.PaymentLog).WithMany(p => p.TblPayments)
                .HasForeignKey(d => d.PaymentLogId)
                .HasConstraintName("FK_tbl_Payment_tbl_PaymentLog");

            entity.HasOne(d => d.User).WithMany(p => p.TblPayments)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_tbl_Payment_tbl_User");
        });

        modelBuilder.Entity<TblPaymentLog>(entity =>
        {
            entity.HasKey(e => e.PaymentLogId);

            entity.ToTable("tbl_PaymentLog");

            entity.Property(e => e.PaymentLogId).HasColumnName("PaymentLogID");
            entity.Property(e => e.Email).HasMaxLength(50);
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
            entity.Property(e => e.PaymentMethods).HasMaxLength(50);
            entity.Property(e => e.PaymentUniqueToken).HasMaxLength(50);
            entity.Property(e => e.Remarks).HasMaxLength(50);
            entity.Property(e => e.Response).HasMaxLength(50);
            entity.Property(e => e.Status).HasMaxLength(500);
            entity.Property(e => e.Token).HasMaxLength(250);
        });

        modelBuilder.Entity<TblProvince>(entity =>
        {
            entity.HasKey(e => e.ProvinceId);

            entity.ToTable("tbl_Province");

            entity.Property(e => e.ProvinceId).HasColumnName("ProvinceID");
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
            entity.Property(e => e.ProvinceName).HasMaxLength(50);
        });

        modelBuilder.Entity<TblRoll>(entity =>
        {
            entity.HasKey(e => e.RollId).HasName("PK_Roll");

            entity.ToTable("tbl_Roll");

            entity.Property(e => e.RollId).HasColumnName("RollID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.RollName).HasMaxLength(50);
        });

        modelBuilder.Entity<TblShippingPolicy>(entity =>
        {
            entity.HasKey(e => e.ShipingId);

            entity.ToTable("tbl_ShippingPolicy");

            entity.Property(e => e.ShipingId).HasColumnName("ShipingID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.PolicyAmount).HasColumnType("decimal(18, 2)");
        });

        modelBuilder.Entity<TblSize>(entity =>
        {
            entity.HasKey(e => e.SizeId).HasName("PK_tbl_Item_Size");

            entity.ToTable("tbl_Size");

            entity.Property(e => e.SizeId).HasColumnName("SizeID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.SizeName).HasMaxLength(50);
        });

        modelBuilder.Entity<TblStatus>(entity =>
        {
            entity.HasKey(e => e.StatusId);

            entity.ToTable("tbl_Status");

            entity.Property(e => e.StatusId).HasColumnName("StatusID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.StatusName).HasMaxLength(50);
        });

        modelBuilder.Entity<TblTag>(entity =>
        {
            entity.HasKey(e => e.TagId);

            entity.ToTable("tbl_Tags");

            entity.Property(e => e.TagId).HasColumnName("TagID");
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.TagName).HasMaxLength(50);
        });

        modelBuilder.Entity<TblUser>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("PK_User");

            entity.ToTable("tbl_User");

            entity.Property(e => e.CreatedBy).HasColumnName("createdBy");
            entity.Property(e => e.Email).HasMaxLength(50);
            entity.Property(e => e.MDelete).HasColumnName("mDelete");
            entity.Property(e => e.Password).HasMaxLength(50);
            entity.Property(e => e.PhoneNumber).HasMaxLength(20);
            entity.Property(e => e.RollId).HasColumnName("RollID");
            entity.Property(e => e.UserName).HasMaxLength(50);

            entity.HasOne(d => d.Roll).WithMany(p => p.TblUsers)
                .HasForeignKey(d => d.RollId)
                .HasConstraintName("FK_tbl_User_tbl_Roll");
        });

        modelBuilder.Entity<TblVoucherCode>(entity =>
        {
            entity.HasKey(e => e.VoucherId);

            entity.ToTable("tbl_VoucherCode");

            entity.Property(e => e.VoucherId).HasColumnName("VoucherID");
            entity.Property(e => e.Mdelete).HasColumnName("mdelete");
            entity.Property(e => e.VoucherDiscount).HasColumnType("decimal(18, 2)");
            entity.Property(e => e.VoucherText).HasMaxLength(500);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
