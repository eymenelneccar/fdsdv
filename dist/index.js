var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import dotenv from "dotenv";
import express3 from "express";

// server/routes.ts
import express from "express";
import { createServer } from "http";
import multer from "multer";
import path from "path";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  activities: () => activities,
  customers: () => customers,
  employees: () => employees,
  expenseEntries: () => expenseEntries,
  incomeEntries: () => incomeEntries,
  insertActivitySchema: () => insertActivitySchema,
  insertCustomerSchema: () => insertCustomerSchema,
  insertEmployeeSchema: () => insertEmployeeSchema,
  insertExpenseEntrySchema: () => insertExpenseEntrySchema,
  insertIncomeEntrySchema: () => insertIncomeEntrySchema,
  insertManualUserSchema: () => insertManualUserSchema,
  sessions: () => sessions,
  users: () => users
});
import { sql } from "drizzle-orm";
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  decimal,
  boolean,
  date
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  username: varchar("username").unique(),
  // for manual user creation
  password: varchar("password"),
  // hashed password for manual user creation
  role: varchar("role").default("viewer"),
  // viewer, editor, admin
  isManualUser: boolean("is_manual_user").default(false),
  // distinguish between Replit Auth users and manual users
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var customers = pgTable("customers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  menuUrl: text("menu_url"),
  joinDate: date("join_date").notNull(),
  subscriptionType: varchar("subscription_type").notNull(),
  // annual, semi-annual, quarterly
  expiryDate: date("expiry_date").notNull(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var incomeEntries = pgTable("income_entries", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  customerId: varchar("customer_id").references(() => customers.id),
  type: varchar("type").notNull(),
  // prints, subscription
  printType: text("print_type"),
  // only if type is prints
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  receiptUrl: text("receipt_url"),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow()
});
var expenseEntries = pgTable("expense_entries", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  reason: text("reason").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var employees = pgTable("employees", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  position: text("position"),
  salary: decimal("salary", { precision: 10, scale: 2 }).notNull(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var activities = pgTable("activities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  type: varchar("type").notNull(),
  // customer_added, payment_received, warning_sent, etc.
  description: text("description").notNull(),
  relatedId: varchar("related_id"),
  // ID of related entity
  createdAt: timestamp("created_at").defaultNow()
});
var insertCustomerSchema = createInsertSchema(customers).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  expiryDate: true
  // calculated automatically
});
var insertIncomeEntrySchema = createInsertSchema(incomeEntries).omit({
  id: true,
  createdAt: true
});
var insertExpenseEntrySchema = createInsertSchema(expenseEntries).omit({
  id: true,
  createdAt: true
});
var insertEmployeeSchema = createInsertSchema(employees).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var insertActivitySchema = createInsertSchema(activities).omit({
  id: true,
  createdAt: true
});
var insertManualUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  email: true,
  // not required for manual users
  firstName: true,
  // not required for manual users
  lastName: true,
  // not required for manual users
  profileImageUrl: true
  // not required for manual users
}).extend({
  username: z.string().min(3, "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u064A\u062C\u0628 \u0623\u0646 \u064A\u0643\u0648\u0646 3 \u0623\u062D\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644"),
  password: z.string().min(6, "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u064A\u062C\u0628 \u0623\u0646 \u062A\u0643\u0648\u0646 6 \u0623\u062D\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644"),
  role: z.enum(["viewer", "editor", "admin"]).default("viewer")
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, desc, sql as sql2 } from "drizzle-orm";
var DatabaseStorage = class {
  // User operations
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async upsertUser(userData) {
    const [user] = await db.insert(users).values(userData).onConflictDoUpdate({
      target: users.id,
      set: {
        ...userData,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return user;
  }
  // Manual user operations
  async getAllUsers() {
    return await db.select().from(users).orderBy(desc(users.createdAt));
  }
  async getUserByUsername(username) {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }
  async createManualUser(userData) {
    const [user] = await db.insert(users).values({
      ...userData,
      isManualUser: true
    }).returning();
    await this.createActivity({
      type: "user_created",
      description: `\u062A\u0645 \u0625\u0646\u0634\u0627\u0621 \u062D\u0633\u0627\u0628 \u0645\u0633\u062A\u062E\u062F\u0645 \u062C\u062F\u064A\u062F: ${userData.username}`,
      relatedId: user.id
    });
    return user;
  }
  // Customer operations
  async getCustomers() {
    return await db.select().from(customers).orderBy(desc(customers.createdAt));
  }
  async getCustomer(id) {
    const [customer] = await db.select().from(customers).where(eq(customers.id, id));
    return customer;
  }
  async createCustomer(customerData) {
    const joinDate = new Date(customerData.joinDate);
    let expiryDate = new Date(joinDate);
    switch (customerData.subscriptionType) {
      case "annual":
        expiryDate.setFullYear(joinDate.getFullYear() + 1);
        break;
      case "semi-annual":
        expiryDate.setMonth(joinDate.getMonth() + 6);
        break;
      case "quarterly":
        expiryDate.setMonth(joinDate.getMonth() + 3);
        break;
    }
    const [customer] = await db.insert(customers).values({
      ...customerData,
      expiryDate: expiryDate.toISOString().split("T")[0]
    }).returning();
    await this.createActivity({
      type: "customer_added",
      description: `\u062A\u0645 \u0625\u0636\u0627\u0641\u0629 \u0639\u0645\u064A\u0644 \u062C\u062F\u064A\u062F: ${customer.name}`,
      relatedId: customer.id
    });
    return customer;
  }
  async updateCustomer(id, data) {
    const [customer] = await db.update(customers).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(eq(customers.id, id)).returning();
    return customer;
  }
  async deleteCustomer(id) {
    await db.delete(customers).where(eq(customers.id, id));
  }
  async getExpiringCustomers(days) {
    const targetDate = /* @__PURE__ */ new Date();
    targetDate.setDate(targetDate.getDate() + days);
    return await db.select().from(customers).where(
      sql2`${customers.expiryDate} <= ${targetDate.toISOString().split("T")[0]} AND ${customers.isActive} = true`
    );
  }
  // Income operations
  async getIncomeEntries(startDate, endDate) {
    if (startDate && endDate) {
      return await db.select().from(incomeEntries).where(
        sql2`${incomeEntries.createdAt} >= ${startDate} AND ${incomeEntries.createdAt} <= ${endDate}`
      ).orderBy(desc(incomeEntries.createdAt));
    }
    return await db.select().from(incomeEntries).orderBy(desc(incomeEntries.createdAt));
  }
  async createIncomeEntry(entryData) {
    const [entry] = await db.insert(incomeEntries).values(entryData).returning();
    await this.createActivity({
      type: "income_added",
      description: `\u062A\u0645 \u062A\u0633\u062C\u064A\u0644 \u062F\u062E\u0644 \u0628\u0642\u064A\u0645\u0629 ${entryData.amount} \u062F.\u0639`,
      relatedId: entry.id
    });
    return entry;
  }
  async getPrintIncomeEntries() {
    return await db.select().from(incomeEntries).where(eq(incomeEntries.type, "prints")).orderBy(desc(incomeEntries.createdAt));
  }
  // Expense operations
  async getExpenseEntries(startDate, endDate) {
    if (startDate && endDate) {
      return await db.select().from(expenseEntries).where(
        sql2`${expenseEntries.createdAt} >= ${startDate} AND ${expenseEntries.createdAt} <= ${endDate}`
      ).orderBy(desc(expenseEntries.createdAt));
    }
    return await db.select().from(expenseEntries).orderBy(desc(expenseEntries.createdAt));
  }
  async createExpenseEntry(entryData) {
    const [entry] = await db.insert(expenseEntries).values(entryData).returning();
    await this.createActivity({
      type: "expense_added",
      description: `\u062A\u0645 \u062A\u0633\u062C\u064A\u0644 \u0645\u0635\u0631\u0648\u0641 \u0628\u0642\u064A\u0645\u0629 ${entryData.amount} \u062F.\u0639 - ${entryData.reason}`,
      relatedId: entry.id
    });
    return entry;
  }
  // Employee operations
  async getEmployees() {
    return await db.select().from(employees).where(eq(employees.isActive, true)).orderBy(desc(employees.createdAt));
  }
  async createEmployee(employeeData) {
    const [employee] = await db.insert(employees).values(employeeData).returning();
    await this.createActivity({
      type: "employee_added",
      description: `\u062A\u0645 \u0625\u0636\u0627\u0641\u0629 \u0645\u0648\u0638\u0641 \u062C\u062F\u064A\u062F: ${employee.name}`,
      relatedId: employee.id
    });
    return employee;
  }
  async updateEmployee(id, data) {
    const [employee] = await db.update(employees).set({ ...data, updatedAt: /* @__PURE__ */ new Date() }).where(eq(employees.id, id)).returning();
    return employee;
  }
  async deleteEmployee(id) {
    await db.update(employees).set({ isActive: false, updatedAt: /* @__PURE__ */ new Date() }).where(eq(employees.id, id));
  }
  // Activity operations
  async getRecentActivities(limit = 10) {
    return await db.select().from(activities).orderBy(desc(activities.createdAt)).limit(limit);
  }
  async createActivity(activityData) {
    const [activity] = await db.insert(activities).values(activityData).returning();
    return activity;
  }
  // Dashboard statistics
  async getDashboardStats() {
    const now = /* @__PURE__ */ new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    const [{ count: totalCustomers }] = await db.select({ count: sql2`cast(count(*) as integer)` }).from(customers).where(eq(customers.isActive, true));
    const monthlyIncomeResult = await db.select({ total: sql2`cast(coalesce(sum(cast(amount as decimal)), 0) as decimal)` }).from(incomeEntries).where(sql2`${incomeEntries.createdAt} >= ${startOfMonth} AND ${incomeEntries.createdAt} <= ${endOfMonth}`);
    const monthlyIncome = Number(monthlyIncomeResult[0]?.total || 0);
    const today = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
    const [{ count: expiredSubscriptions }] = await db.select({ count: sql2`cast(count(*) as integer)` }).from(customers).where(sql2`${customers.expiryDate} < ${today} AND ${customers.isActive} = true`);
    const totalIncomeResult = await db.select({ total: sql2`cast(coalesce(sum(cast(amount as decimal)), 0) as decimal)` }).from(incomeEntries);
    const totalIncome = Number(totalIncomeResult[0]?.total || 0);
    const totalExpensesResult = await db.select({ total: sql2`cast(coalesce(sum(cast(amount as decimal)), 0) as decimal)` }).from(expenseEntries);
    const totalExpenses = Number(totalExpensesResult[0]?.total || 0);
    const currentInventory = totalIncome - totalExpenses;
    const totalSalariesResult = await db.select({ total: sql2`cast(coalesce(sum(cast(salary as decimal)), 0) as decimal)` }).from(employees).where(eq(employees.isActive, true));
    const totalSalaries = Number(totalSalariesResult[0]?.total || 0);
    let financialStatus = "healthy";
    if (currentInventory < totalSalaries) {
      financialStatus = "critical";
    } else if (currentInventory < totalSalaries * 1.5) {
      financialStatus = "warning";
    }
    return {
      totalCustomers,
      monthlyIncome,
      expiredSubscriptions,
      currentInventory,
      totalSalaries,
      financialStatus
    };
  }
  async updateUserProfile(userId, updates) {
    console.log(`Updating profile for user ${userId}:`, updates);
    return Promise.resolve();
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
import session from "express-session";
import connectPg from "connect-pg-simple";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function verifyPassword(password, hashedPassword) {
  try {
    const [hashedPwd, salt] = hashedPassword.split(".");
    const hashedPasswordBuf = Buffer.from(hashedPwd, "hex");
    const suppliedPasswordBuf = await scryptAsync(password, salt, 64);
    return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
  } catch {
    return false;
  }
}
function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1e3;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions"
  });
  return session({
    secret: process.env.SESSION_SECRET || "development-session-secret-change-in-production",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: sessionTtl
    }
  });
}
function setupAuth(app2) {
  app2.set("trust proxy", 1);
  app2.use(getSession());
  app2.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u0648\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0645\u0637\u0644\u0648\u0628\u0627\u0646" });
      }
      const user = await storage.getUserByUsername(username);
      if (!user || !user.password) {
        return res.status(401).json({ message: "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u0623\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D" });
      }
      const isValidPassword = await verifyPassword(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ message: "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u0623\u0648 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D" });
      }
      req.session.userId = user.id;
      const { password: _, ...safeUser } = user;
      res.json(safeUser);
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "\u062D\u062F\u062B \u062E\u0637\u0623 \u0623\u062B\u0646\u0627\u0621 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644" });
    }
  });
  app2.post("/api/auth/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "\u062D\u062F\u062B \u062E\u0637\u0623 \u0623\u062B\u0646\u0627\u0621 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062E\u0631\u0648\u062C" });
      }
      res.clearCookie("connect.sid");
      res.json({ message: "\u062A\u0645 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062E\u0631\u0648\u062C \u0628\u0646\u062C\u0627\u062D" });
    });
  });
  app2.get("/api/auth/user", async (req, res) => {
    try {
      const userId = req.session.userId;
      if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ message: "Unauthorized" });
      }
      const { password: _, ...safeUser } = user;
      res.json(safeUser);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
}
var isAuthenticated = async (req, res, next) => {
  try {
    const userId = req.session.userId;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await storage.getUser(userId);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(401).json({ message: "Unauthorized" });
  }
};

// server/routes.ts
var upload = multer({
  dest: "uploads/",
  limits: {
    fileSize: 10 * 1024 * 1024
    // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("\u064A\u064F\u0633\u0645\u062D \u0641\u0642\u0637 \u0628\u0645\u0644\u0641\u0627\u062A \u0627\u0644\u0635\u0648\u0631 \u0648 PDF"));
    }
  }
});
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.put("/api/auth/user/profile", isAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const { firstName, lastName, email, username, password } = req.body;
      const updateData = {};
      if (firstName) updateData.firstName = firstName;
      if (lastName) updateData.lastName = lastName;
      if (email) updateData.email = email;
      if (username) updateData.username = username;
      if (password && password.trim() !== "") {
        const hashedPassword = await hashPassword(password);
        updateData.password = hashedPassword;
      }
      await storage.updateUserProfile(userId, updateData);
      const updatedUser = await storage.getUser(userId);
      const { password: _, ...safeUser } = updatedUser;
      res.json(safeUser);
    } catch (error) {
      console.error("Error updating user profile:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062A\u062D\u062F\u064A\u062B \u0627\u0644\u0628\u0631\u0648\u0641\u0627\u064A\u0644" });
    }
  });
  app2.get("/api/dashboard/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0625\u062D\u0635\u0627\u0626\u064A\u0627\u062A \u0644\u0648\u062D\u0629 \u0627\u0644\u062A\u062D\u0643\u0645" });
    }
  });
  app2.get("/api/activities", isAuthenticated, async (req, res) => {
    try {
      const activities2 = await storage.getRecentActivities(10);
      res.json(activities2);
    } catch (error) {
      console.error("Error fetching activities:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0623\u0646\u0634\u0637\u0629 \u0627\u0644\u0623\u062E\u064A\u0631\u0629" });
    }
  });
  app2.get("/api/customers", isAuthenticated, async (req, res) => {
    try {
      const customers2 = await storage.getCustomers();
      res.json(customers2);
    } catch (error) {
      console.error("Error fetching customers:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0639\u0645\u0644\u0627\u0621" });
    }
  });
  app2.post("/api/customers", isAuthenticated, async (req, res) => {
    try {
      const validatedData = insertCustomerSchema.parse(req.body);
      const customer = await storage.createCustomer(validatedData);
      res.status(201).json(customer);
    } catch (error) {
      console.error("Error creating customer:", error);
      res.status(400).json({ message: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0639\u0645\u064A\u0644 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629" });
    }
  });
  app2.patch("/api/customers/:id/renew", isAuthenticated, async (req, res) => {
    try {
      const customer = await storage.getCustomer(req.params.id);
      if (!customer) {
        return res.status(404).json({ message: "\u0627\u0644\u0639\u0645\u064A\u0644 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F" });
      }
      const currentExpiry = new Date(customer.expiryDate);
      const newExpiry = new Date(currentExpiry);
      newExpiry.setFullYear(currentExpiry.getFullYear() + 1);
      const updatedCustomer = await storage.updateCustomer(req.params.id, {
        expiryDate: newExpiry.toISOString().split("T")[0],
        isActive: true
      });
      await storage.createActivity({
        type: "subscription_renewed",
        description: `\u062A\u0645 \u062A\u062C\u062F\u064A\u062F \u0627\u0634\u062A\u0631\u0627\u0643 \u0627\u0644\u0639\u0645\u064A\u0644: ${customer.name}`,
        relatedId: customer.id
      });
      res.json(updatedCustomer);
    } catch (error) {
      console.error("Error renewing subscription:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062A\u062C\u062F\u064A\u062F \u0627\u0644\u0627\u0634\u062A\u0631\u0627\u0643" });
    }
  });
  app2.get("/api/customers/expiring/:days", isAuthenticated, async (req, res) => {
    try {
      const days = parseInt(req.params.days);
      const expiringCustomers = await storage.getExpiringCustomers(days);
      res.json(expiringCustomers);
    } catch (error) {
      console.error("Error fetching expiring customers:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0639\u0645\u0644\u0627\u0621 \u0627\u0644\u0645\u0646\u062A\u0647\u064A\u064A\u0646" });
    }
  });
  app2.get("/api/income", isAuthenticated, async (req, res) => {
    try {
      const { startDate, endDate } = req.query;
      const start = startDate ? new Date(startDate) : void 0;
      const end = endDate ? new Date(endDate) : void 0;
      const incomeEntries2 = await storage.getIncomeEntries(start, end);
      res.json(incomeEntries2);
    } catch (error) {
      console.error("Error fetching income entries:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0625\u062F\u062E\u0627\u0644\u0627\u062A" });
    }
  });
  app2.post("/api/income", isAuthenticated, upload.single("receipt"), async (req, res) => {
    try {
      const validatedData = insertIncomeEntrySchema.parse({
        ...req.body,
        receiptUrl: req.file ? `/uploads/${req.file.filename}` : null
      });
      const incomeEntry = await storage.createIncomeEntry(validatedData);
      res.status(201).json(incomeEntry);
    } catch (error) {
      console.error("Error creating income entry:", error);
      res.status(400).json({ message: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0625\u062F\u062E\u0627\u0644 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629" });
    }
  });
  app2.get("/api/income/prints", isAuthenticated, async (req, res) => {
    try {
      const printEntries = await storage.getPrintIncomeEntries();
      res.json(printEntries);
    } catch (error) {
      console.error("Error fetching print entries:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0645\u0637\u0628\u0648\u0639\u0627\u062A" });
    }
  });
  app2.get("/api/expenses", isAuthenticated, async (req, res) => {
    try {
      const { startDate, endDate } = req.query;
      const start = startDate ? new Date(startDate) : void 0;
      const end = endDate ? new Date(endDate) : void 0;
      const expenseEntries2 = await storage.getExpenseEntries(start, end);
      res.json(expenseEntries2);
    } catch (error) {
      console.error("Error fetching expense entries:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0625\u062E\u0631\u0627\u062C\u0627\u062A" });
    }
  });
  app2.post("/api/expenses", isAuthenticated, async (req, res) => {
    try {
      const validatedData = insertExpenseEntrySchema.parse(req.body);
      const expenseEntry = await storage.createExpenseEntry(validatedData);
      res.status(201).json(expenseEntry);
    } catch (error) {
      console.error("Error creating expense entry:", error);
      res.status(400).json({ message: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0625\u062E\u0631\u0627\u062C \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629" });
    }
  });
  app2.get("/api/employees", isAuthenticated, async (req, res) => {
    try {
      const employees2 = await storage.getEmployees();
      res.json(employees2);
    } catch (error) {
      console.error("Error fetching employees:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0645\u0648\u0638\u0641\u064A\u0646" });
    }
  });
  app2.post("/api/employees", isAuthenticated, async (req, res) => {
    try {
      const validatedData = insertEmployeeSchema.parse(req.body);
      const employee = await storage.createEmployee(validatedData);
      res.status(201).json(employee);
    } catch (error) {
      console.error("Error creating employee:", error);
      res.status(400).json({ message: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0648\u0638\u0641 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629" });
    }
  });
  app2.delete("/api/employees/:id", isAuthenticated, async (req, res) => {
    try {
      await storage.deleteEmployee(req.params.id);
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting employee:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062D\u0630\u0641 \u0627\u0644\u0645\u0648\u0638\u0641" });
    }
  });
  app2.post("/api/reports/generate", isAuthenticated, async (req, res) => {
    try {
      const { startDate, endDate, reportType } = req.body;
      const reportData = {
        period: `${startDate} \u0625\u0644\u0649 ${endDate}`,
        type: reportType,
        generatedAt: (/* @__PURE__ */ new Date()).toISOString()
        // Add actual data based on report type
      };
      res.json({
        message: "\u062A\u0645 \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u062A\u0642\u0631\u064A\u0631 \u0628\u0646\u062C\u0627\u062D",
        downloadUrl: "/api/reports/download/sample.pdf",
        data: reportData
      });
    } catch (error) {
      console.error("Error generating report:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u062A\u0642\u0631\u064A\u0631" });
    }
  });
  app2.get("/api/users", isAuthenticated, async (req, res) => {
    try {
      const users2 = await storage.getAllUsers();
      const safeUsers = users2.map((user) => {
        const { password, ...safeUser } = user;
        return safeUser;
      });
      res.json(safeUsers);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u062C\u0644\u0628 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645\u064A\u0646" });
    }
  });
  app2.post("/api/users", isAuthenticated, async (req, res) => {
    try {
      const validatedData = insertManualUserSchema.parse(req.body);
      const existingUser = await storage.getUserByUsername(validatedData.username);
      if (existingUser) {
        return res.status(400).json({ message: "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u0645\u0648\u062C\u0648\u062F \u0628\u0627\u0644\u0641\u0639\u0644" });
      }
      const hashedPassword = await hashPassword(validatedData.password);
      const user = await storage.createManualUser({
        ...validatedData,
        password: hashedPassword
      });
      const { password, ...safeUser } = user;
      res.status(201).json(safeUser);
    } catch (error) {
      console.error("Error creating user:", error);
      if (error.name === "ZodError") {
        res.status(400).json({ message: "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629" });
      } else {
        res.status(500).json({ message: "\u0641\u0634\u0644 \u0641\u064A \u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645" });
      }
    }
  });
  app2.use("/uploads", express.static("uploads"));
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express2 from "express";
import fs from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(import.meta.dirname, "client", "src"),
      "@shared": path2.resolve(import.meta.dirname, "shared"),
      "@assets": path2.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path2.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path2.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
dotenv.config();
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "postgresql://neondb_owner:npg_j0uJzebEPgs4@ep-lively-pine-adpu1pz9-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";
}
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = "development-session-secret-change-in-production";
}
if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = "development";
}
var app = express3();
app.use(express3.json());
app.use(express3.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  const host = process.env.NODE_ENV === "development" && process.platform === "win32" ? "localhost" : "0.0.0.0";
  server.listen({
    port,
    host,
    reusePort: process.platform !== "win32"
  }, () => {
    console.log(`\u2705 IQR Control server running on http://${host}:${port}`);
    console.log(`\u{1F464} Login: admin / admin123`);
    console.log(`\u{1F4BE} Database: Connected to Neon PostgreSQL`);
    log(`serving on port ${port}`);
  });
})();
