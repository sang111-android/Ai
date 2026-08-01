# Pishi AI Dashboard

داشبورد فارسی چت چندمدلی با ثبت‌نام، تاریخچه، پلن، کد لایسنس و پنل مدیریت. Backend و Frontend در یک سرویس Node.js اجرا می‌شوند و داده‌ها در PostgreSQL نگهداری می‌شوند.

## امکانات

- ثبت‌نام، ورود و نشست امن ۳۰ روزه
- چت با APIهای سازگار با OpenAI (`/chat/completions`)
- مدل‌های متعدد و قفل‌گذاری براساس پلن
- نگهداری تاریخچه و عنوان خودکار گفت‌وگوها
- فعال‌سازی پلن با کد لایسنس، محدودیت استفاده و انقضا
- پنل ادمین برای Base URL، API Key، مدل‌ها، لایسنس‌ها و کاربران
- رمزنگاری API Key با AES-256-GCM
- رابط فارسی RTL و واکنش‌گرا

## استقرار روی Railway

1. این پوشه را در یک مخزن GitHub قرار دهید و در Railway گزینه **Deploy from GitHub repo** را بزنید.
2. داخل همان Project روی **+ New → Database → PostgreSQL** بزنید.
3. در سرویس اپ، بخش **Variables** این موارد را اضافه کنید:

```env
DATABASE_URL=${{Postgres.DATABASE_URL}}
APP_ENCRYPTION_KEY=یک-رشته-تصادفی-طولانی-حداقل-۳۲-کاراکتر
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=یک-رمز-قوی-حداقل-۸-کاراکتر
NODE_ENV=production
```

4. مطمئن شوید متغیر `DATABASE_URL` واقعاً به سرویس PostgreSQL اشاره می‌کند. اگر نام سرویس دیتابیس شما `Postgres` نیست، به‌جای نوشتن دستی مقدار، از **Add Reference** در Railway استفاده کنید و متغیر `DATABASE_URL` همان سرویس را انتخاب کنید.
5. در Settings سرویس، از بخش Networking یک Public Domain بسازید.
6. پس از اولین اجرا با `ADMIN_EMAIL` و `ADMIN_PASSWORD` وارد شوید؛ در **پنل مدیریت → اتصال AI**، Base URL و API Key را وارد کنید.
7. در پنل مدیریت، شناسه دقیق مدل‌های سرویس‌دهنده را بسازید و حداقل پلن هر مدل را انتخاب کنید.

## بررسی وضعیت استقرار

آدرس `/health` را در انتهای دامنه باز کنید. پاسخ سالم باید شامل موارد زیر باشد:

```json
{"service":"pishi-ai","ok":true,"database":"connected","configuration":"ok"}
```

اگر `configuration` خطا نشان داد، متغیرهای Railway ناقص هستند. اگر `database` برابر `waiting` بود، اتصال `DATABASE_URL` یا سرویس PostgreSQL را بررسی کنید. نسخه 1.0.1 حتی هنگام آماده نبودن دیتابیس وب‌سرور را بالا می‌آورد تا Healthcheck بی‌دلیل شکست نخورد و خطای واقعی قابل مشاهده باشد.

### آیا Disk/Volume لازم است؟

خیر. برای این پروژه **PostgreSQL لازم است ولی Volume جدا برای سرویس اپ لازم نیست**. تاریخچه، کاربران، نشست‌ها و لایسنس‌ها همگی در PostgreSQL ذخیره می‌شوند. خود سرویس PostgreSQL در Railway فضای پایدار خود را دارد.

## اجرای محلی

Node.js 20+ و PostgreSQL لازم است:

```bash
cp .env.example .env
npm install
set -a && source .env && set +a
npm start
```

سپس `http://localhost:3000` را باز کنید.

## آدرس کامل API

آدرس باید endpoint کامل درخواست چت باشد، مثلاً:

- `https://api.openai.com/v1/chat/completions`
- `https://openrouter.ai/api/v1/chat/completions`
- آدرس کامل endpoint سرویس اختصاصی سازگار با OpenAI

برنامه آدرس را دقیقاً همان‌طور که ادمین وارد می‌کند استفاده می‌کند و هیچ مسیر یا عبارتی به انتهای آن اضافه نمی‌کند.

## نکات تولید

- مقدار `APP_ENCRYPTION_KEY` را بعد از ذخیره API Key تغییر ندهید؛ در غیر این صورت کلید قبلی قابل رمزگشایی نیست.
- قبل از استفاده واقعی، برای PostgreSQL بکاپ دوره‌ای فعال کنید.
- برای مصرف بالا بهتر است محدودیت پیام/توکن، ثبت هزینه و صف درخواست اضافه شود.
- ادمین اولیه فقط وقتی ساخته می‌شود که کاربری با `ADMIN_EMAIL` وجود نداشته باشد.
