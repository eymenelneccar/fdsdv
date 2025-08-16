@echo off
echo Creating .env file for IQR Control...

(
echo DATABASE_URL=postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require^&channel_binding=require
echo SESSION_SECRET=development-session-secret-change-in-production
echo NODE_ENV=development
echo PORT=5000
) > .env

echo ✓ .env file created successfully!
echo.
echo File contents:
type .env
echo.
echo Now you can run: start-windows.cmd
pause