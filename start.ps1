# PowerShell script to start the development server
Write-Host "Starting IQR Control Development Server..." -ForegroundColor Green

# Set environment variables
$env:NODE_ENV = "development"
$env:PORT = "5000"

# Always create/overwrite .env file to ensure it's correct
Write-Host "Creating .env file..." -ForegroundColor Yellow
$envContent = @"
DATABASE_URL=postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require
SESSION_SECRET=development-session-secret-change-in-production
NODE_ENV=development
PORT=5000
"@
$envContent | Out-File -FilePath ".env" -Encoding UTF8 -NoNewline
Write-Host ".env file created successfully!" -ForegroundColor Green

# Verify .env file was created
if (Test-Path ".env") {
    Write-Host "✓ .env file exists" -ForegroundColor Green
    Write-Host "Contents:" -ForegroundColor Cyan
    Get-Content ".env" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "✗ Failed to create .env file" -ForegroundColor Red
}

# Start the server
Write-Host "Starting server on http://localhost:5000" -ForegroundColor Cyan
Write-Host "Login credentials: admin / admin123" -ForegroundColor Yellow

try {
    & npx tsx server/index.ts
} catch {
    Write-Host "Error starting server: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}