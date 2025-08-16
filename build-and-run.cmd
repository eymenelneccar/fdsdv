@echo off
echo ====================================
echo    IQR Control - تجميع وتشغيل
echo ====================================
echo جاري تجميع المشروع...

REM Build the project
call npm run build

if %ERRORLEVEL% NEQ 0 (
    echo ❌ فشل في تجميع المشروع
    pause
    exit /b 1
)

echo ✅ تم تجميع المشروع بنجاح
echo جاري تشغيل الخادم...
echo Dashboard: http://localhost:5000
echo Login: admin / admin123
echo ====================================

REM Set environment variables and run
set DATABASE_URL=postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require^&channel_binding=require
set SESSION_SECRET=development-session-secret-change-in-production
set NODE_ENV=production
set PORT=5000

node dist/index.js