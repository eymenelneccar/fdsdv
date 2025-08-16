# Script to create .env file
Write-Host "Creating .env file for IQR Control..." -ForegroundColor Green

$envContent = "DATABASE_URL=postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require`nSESSION_SECRET=development-session-secret-change-in-production`nNODE_ENV=development`nPORT=5000"

try {
    $envContent | Out-File -FilePath ".env" -Encoding ASCII -NoNewline
    Write-Host "✓ .env file created successfully!" -ForegroundColor Green
    
    # Verify content
    if (Test-Path ".env") {
        Write-Host "`nFile contents:" -ForegroundColor Cyan
        Get-Content ".env" | ForEach-Object { Write-Host "  $_" }
        Write-Host "`nNow you can run: npm run dev or .\start.ps1" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error creating .env file: $_" -ForegroundColor Red
}

Read-Host "`nPress Enter to continue"