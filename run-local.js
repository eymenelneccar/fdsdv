// Simple script to run the server locally with all environment variables set
process.env.DATABASE_URL = 'postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';
process.env.SESSION_SECRET = 'development-session-secret-change-in-production';
process.env.NODE_ENV = 'development';
process.env.PORT = '5000';

console.log('🚀 Starting IQR Control Development Server...');
console.log('📊 Dashboard URL: http://localhost:5000');
console.log('👤 Login: admin / admin123');
console.log('💾 Database: Connected to Neon PostgreSQL');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

// Import and run the server
import('./server/index.ts').catch(console.error);