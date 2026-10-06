# HSE Professional Website

نسخه واقعی Full-Stack سایت HSE با Node.js/Express و PostgreSQL.

## امکانات
- سایت فارسی RTL و واکنش‌گرا
- پنل مدیریت امن با ایمیل/رمز
- تغییر رمز مدیریت
- مدیریت اطلاعات اصلی سایت
- افزودن/ویرایش/حذف خدمات، پروژه‌ها، شرح خدمات و مدارک
- ثبت پیام‌های تماس
- شمارنده بازدید
- داشبورد مدیریتی
- ثبت Audit Log
- آپلود تصویر در API
- PostgreSQL برای ذخیره‌سازی واقعی

## استقرار روی Render
Build Command:
`npm install`

Start Command:
`npm start`

متغیرهای محیطی:
- DATABASE_URL
- JWT_SECRET
- ADMIN_EMAIL
- ADMIN_PASSWORD

`render.yaml` نیز برای راه‌اندازی آماده شده است.

### نکته مهم
فایل‌های آپلودی محلی روی Render بدون فضای ذخیره‌سازی پایدار قابل اتکا نیستند. برای نسخه production باید تصاویر روی Object Storage/CDN ذخیره شوند یا از راهکار ذخیره‌سازی پایدار استفاده شود.

برای نسخه رایگان Render، سرویس و دیتابیس محدودیت‌های خاص خود را دارند و برای production دائمی مناسب نیستند.
