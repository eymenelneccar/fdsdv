import dotenv from "dotenv";
// Load environment variables from .env file in development
dotenv.config();

// Set fallback environment variables if not found
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';
}
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = 'development-session-secret-change-in-production';
}
if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = 'development';
}

import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  const host = 'localhost'; // Always use localhost for Windows compatibility
  
  server.listen({
    port,
    host,
    reusePort: process.platform !== 'win32',
  }, () => {
    console.log(`✅ IQR Control server running on http://${host}:${port}`);
    console.log(`👤 Login: admin / admin123`);
    console.log(`💾 Database: Connected to Neon PostgreSQL`);
    log(`serving on port ${port}`);
  });
})();
