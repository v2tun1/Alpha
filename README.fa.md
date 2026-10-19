# Alpha

نسخه‌ی سازمان‌دهی‌شده‌ی پروژه Alpha برای Cloudflare Workers.

## ساختار

- `src/worker.js`: کد Worker
- `public/data/`: فایل‌های داده و فهرست پروکسی‌ها
- `public/assets/images/`: تصاویر
- `public/tools/`: اسکریپت مدیریت ریلی و بسته‌ی اسکنر
- `public/vendor/`: فایل JavaScript مبهم‌سازی‌شده‌ی نگه‌داری‌شده از بسته‌ی اصلی
- `public/downloads/worker-source.js`: نسخه‌ی قابل دریافت سورس که پیش از دیپلوی همگام می‌شود
- `wrangler.jsonc`: تنظیمات Worker، فایل‌های ایستا و D1

## بررسی و دیپلوی

```bash
npm install
npm run check
npm run deploy:dry
npm run deploy
```

پیش از دیپلوی، شناسه‌ی D1 در `wrangler.jsonc` را با دیتابیس حساب Cloudflare خودت تطبیق بده. فایل‌های داده‌ی پروژه اکنون از `public/` ارائه می‌شوند؛ با این حال APIهای Cloudflare و برخی سرویس‌های خارجی که قابلیت‌های برنامه به آن‌ها نیاز دارد همچنان بیرونی هستند.
