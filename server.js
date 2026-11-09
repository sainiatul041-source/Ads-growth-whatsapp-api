
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const multer = require("multer");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const BUCKET = "payment-screenshots";

for (const k of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY", "JWT_SECRET"]) {
  if (!process.env[k]) {
    console.error("Missing environment variable:", k);
    process.exit(1);
  }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters");
  process.exit(1);
}

const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false }
});
const authDB = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
  auth: { persistSession: false }
});

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true,
  credentials: true
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    cb(null, ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype));
  }
});

const clean = v => String(v || "").trim();
const token = data => jwt.sign(data, process.env.JWT_SECRET, { expiresIn: "7d" });
const hashKey = key => crypto.createHash("sha256").update(key).digest("hex");
const newKey = () => "ag_live_" + crypto.randomBytes(32).toString("hex");
const newPassword = () => crypto.randomBytes(6).toString("hex");

function fail(res, err, message) {
  console.error(message, err?.message || err);
  return res.status(500).json({ success: false, message });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  try {
    if (!h.startsWith("Bearer ")) throw new Error();
    req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: "Login required or expired." });
  }
}

const admin = (req, res, next) => req.user?.role === "admin"
  ? next()
  : res.status(403).json({ success: false, message: "Admin access required." });

const client = (req, res, next) => req.user?.role === "client"
  ? next()
  : res.status(403).json({ success: false, message: "Customer access required." });

/* HEALTH */

app.get("/", (req, res) => res.json({
  success: true, service: "ADS GROWTH", status: "running"
}));
app.get("/health", (req, res) => res.json({ success: true, status: "healthy" }));

/* REGISTER */

app.post("/api/register", limiter, async (req, res) => {
  try {
    const full_name = clean(req.body.full_name);
    const phone = clean(req.body.phone);
    const email = clean(req.body.email).toLowerCase();
    const plan = clean(req.body.plan);
    const prices = { Starter: 4999, Business: 7999, Enterprise: 9999 };

    if (!full_name || !phone || !email || !prices[plan]) {
      return res.status(400).json({ success: false, message: "Enter all details and a valid plan." });
    }

    const { data: old, error: e1 } = await db.from("customers")
      .select("id").or(`email.eq.${email},phone.eq.${phone}`).limit(1);
    if (e1) throw e1;
    if (old?.length) return res.status(409).json({ success: false, message: "Email or phone already registered." });

    const { data, error } = await db.from("customers").insert({
      full_name, phone, email, plan, amount: prices[plan], status: "pending"
    }).select("id,full_name,phone,email,plan,amount,status,created_at").single();
    if (error) throw error;

    res.status(201).json({ success: true, message: "Registration successful.", customer: data });
  } catch (e) { fail(res, e, "Registration failed."); }
});

/* PAYMENT UPLOAD */

async function paymentUpload(req, res) {
  try {
    const customer_id = clean(req.body.customer_id);
    const utr = clean(req.body.utr);
    if (!customer_id || !utr || !req.file) {
      return res.status(400).json({ success: false, message: "Customer ID, UTR and screenshot required." });
    }

    const { data: customer, error: ce } = await db.from("customers")
      .select("id,status").eq("id", customer_id).maybeSingle();
    if (ce) throw ce;
    if (!customer) return res.status(404).json({ success: false, message: "Customer not found." });
    if (customer.status === "approved") return res.status(400).json({ success: false, message: "Customer already approved." });

    const { data: duplicate, error: de } = await db.from("payments")
      .select("id").eq("utr", utr).limit(1);
    if (de) throw de;
    if (duplicate?.length) return res.status(409).json({ success: false, message: "UTR already submitted." });

    const ext = req.file.mimetype === "image/png" ? "png" :
      req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const path = customer_id + "/" + Date.now() + "-" + crypto.randomBytes(5).toString("hex") + "." + ext;

    const { error: se } = await db.storage.from(BUCKET).upload(path, req.file.buffer, {
      contentType: req.file.mimetype, upsert: false
    });
    if (se) throw se;

    const { data, error } = await db.from("payments").insert({
      customer_id, utr, screenshot_path: path, status: "pending"
    }).select("id,customer_id,utr,status,created_at").single();

    if (error) {
      await db.storage.from(BUCKET).remove([path]);
      throw error;
    }
    res.status(201).json({ success: true, message: "Payment submitted.", payment: data });
  } catch (e) { fail(res, e, "Payment upload failed."); }
}

app.post("/api/payment/upload", upload.single("screenshot"), paymentUpload);
app.post("/api/payments/upload", upload.single("screenshot"), paymentUpload);

/* ADMIN LOGIN */

app.post("/api/admin/login", limiter, async (req, res) => {
  try {
    const email = clean(req.body.email).toLowerCase();
    const password = clean(req.body.password);
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required." });

    const { data: a, error: ae } = await authDB.auth.signInWithPassword({ email, password });
    if (ae || !a?.user) return res.status(401).json({ success: false, message: "Invalid admin login." });

    const { data: row, error } = await db.from("admin_users")
      .select("user_id").eq("user_id", a.user.id).maybeSingle();
    if (error) throw error;
    if (!row) return res.status(403).json({ success: false, message: "Admin not authorized." });

    res.json({
      success: true,
      token: token({ id: a.user.id, email: a.user.email, role: "admin" }),
      admin: { id: a.user.id, email: a.user.email }
    });
  } catch (e) { fail(res, e, "Admin login failed."); }
});

app.get("/api/admin/me", auth, admin, (req, res) => {
  res.json({ success: true, admin: { id: req.user.id, email: req.user.email } });
});

/* ADMIN CUSTOMERS */

app.get("/api/admin/customers", auth, admin, async (req, res) => {
  try {
    const { data, error } = await db.from("customers")
      .select("id,full_name,phone,email,plan,amount,status,created_at")
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, customers: data || [] });
  } catch (e) { fail(res, e, "Could not load customers."); }
});

/* ADMIN PAYMENTS */

app.get("/api/admin/payments", auth, admin, async (req, res) => {
  try {
    const { data, error } = await db.from("payments")
      .select("id,customer_id,utr,screenshot_path,status,created_at,verified_at")
      .order("created_at", { ascending: false });
    if (error) throw error;

    const payments = await Promise.all((data || []).map(async p => {
      let screenshot_url = null;
      if (p.screenshot_path) {
        const { data: signed } = await db.storage.from(BUCKET)
          .createSignedUrl(p.screenshot_path, 3600);
        screenshot_url = signed?.signedUrl || null;
      }
      return { ...p, screenshot_url };
    }));
    res.json({ success: true, payments });
  } catch (e) { fail(res, e, "Could not load payments."); }
});

/* APPROVE PAYMENT */

app.post("/api/admin/payments/:id/approve", auth, admin, async (req, res) => {
  try {
    const { data: p, error: pe } = await db.from("payments")
      .select("id,customer_id").eq("id", req.params.id).maybeSingle();
    if (pe) throw pe;
    if (!p) return res.status(404).json({ success: false, message: "Payment not found." });

    const { error: e1 } = await db.from("payments").update({
      status: "approved", verified_at: new Date().toISOString()
    }).eq("id", p.id);
    if (e1) throw e1;

    const { error: e2 } = await db.from("customers")
      .update({ status: "approved" }).eq("id", p.customer_id);
    if (e2) throw e2;

    res.json({ success: true, message: "Payment approved." });
  } catch (e) { fail(res, e, "Payment approval failed."); }
});

/* REJECT PAYMENT */

app.post("/api/admin/payments/:id/reject", auth, admin, async (req, res) => {
  try {
    const { data, error } = await db.from("payments")
      .update({ status: "rejected" }).eq("id", req.params.id)
      .select("id").maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, message: "Payment not found." });
    res.json({ success: true, message: "Payment rejected." });
  } catch (e) { fail(res, e, "Payment rejection failed."); }
});

/* ADMIN GENERATE API KEY AND PASSWORD */

app.post("/api/admin/customers/:id/api-key", auth, admin, async (req, res) => {
  try {
    const id = req.params.id;
    const { data: c, error: ce } = await db.from("customers")
      .select("id,full_name,email,status,password_hash").eq("id", id).maybeSingle();
    if (ce) throw ce;
    if (!c) return res.status(404).json({ success: false, message: "Customer not found." });
    if (c.status !== "approved") return res.status(400).json({ success: false, message: "Payment not approved." });

    const { data: active, error: ke } = await db.from("api_keys")
      .select("id").eq("customer_id", id).eq("status", "active").limit(1);
    if (ke) throw ke;
    if (active?.length) return res.status(409).json({ success: false, message: "Active key already exists. Revoke it first." });

    let temporary_password = null;
    if (!c.password_hash) {
      temporary_password = newPassword();
      const { error } = await db.from("customers").update({
        password_hash: await bcrypt.hash(temporary_password, 12)
      }).eq("id", id);
      if (error) throw error;
    }

    const api_key = newKey();
    const { data: key, error } = await db.from("api_keys").insert({
      customer_id: id,
      key_hash: hashKey(api_key),
      key_prefix: api_key.slice(0, 16),
      status: "active"
    }).select("id,customer_id,key_prefix,status,created_at").single();
    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "API key generated. Save it securely.",
      customer_id: id,
      customer_name: c.full_name,
      api_key,
      temporary_password,
      key
    });
  } catch (e) { fail(res, e, "API key generation failed."); }
});

/* ADMIN API KEY LIST */

app.get("/api/admin/api-keys", auth, admin, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys")
      .select("id,customer_id,key_prefix,status,created_at")
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, api_keys: data || [] });
  } catch (e) { fail(res, e, "Could not load API keys."); }
});

/* ADMIN CHANGE KEY STATUS */

app.patch("/api/admin/api-keys/:id/status", auth, admin, async (req, res) => {
  try {
    const status = clean(req.body.status);
    if (!["active", "revoked"].includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid status." });
    }
    const { data, error } = await db.from("api_keys").update({ status })
      .eq("id", req.params.id)
      .select("id,customer_id,key_prefix,status,created_at").single();
    if (error) throw error;
    res.json({ success: true, key: data });
  } catch (e) { fail(res, e, "API key status update failed."); }
});

/* CUSTOMER LOGIN */

app.post("/api/client/login", limiter, async (req, res) => {
  try {
    const login = clean(req.body.email || req.body.phone).toLowerCase();
    const password = clean(req.body.password);
    if (!login || !password) return res.status(400).json({ success: false, message: "Email/phone and password required." });

    const column = login.includes("@") ? "email" : "phone";
    const { data: c, error } = await db.from("customers")
      .select("id,full_name,email,phone,status,password_hash")
      .eq(column, login).maybeSingle();
    if (error) throw error;
    if (!c?.password_hash || !await bcrypt.compare(password, c.password_hash)) {
      return res.status(401).json({ success: false, message: "Invalid login or password." });
    }
    if (c.status !== "approved") return res.status(403).json({ success: false, message: "Account not approved." });

    res.json({
      success: true,
      token: token({ id: c.id, role: "client" }),
      customer: { id: c.id, full_name: c.full_name, email: c.email, phone: c.phone, status: c.status }
    });
  } catch (e) { fail(res, e, "Customer login failed."); }
});

/* CUSTOMER DASHBOARD */

app.get("/api/client/dashboard", auth, client, async (req, res) => {
  try {
    const { data: customer, error: e1 } = await db.from("customers")
      .select("id,full_name,phone,email,plan,amount,status,created_at")
      .eq("id", req.user.id).maybeSingle();
    if (e1) throw e1;
    if (!customer) return res.status(404).json({ success: false, message: "Customer not found." });

    const { data: payments, error: e2 } = await db.from("payments")
      .select("id,utr,status,created_at,verified_at")
      .eq("customer_id", req.user.id).order("created_at", { ascending: false });
    if (e2) throw e2;

    const { data: api_keys, error: e3 } = await db.from("api_keys")
      .select("id,key_prefix,status,created_at")
      .eq("customer_id", req.user.id).order("created_at", { ascending: false });
    if (e3) throw e3;

    res.json({ success: true, customer, payments: payments || [], api_keys: api_keys || [] });
  } catch (e) { fail(res, e, "Could not load dashboard."); }
});

/* CUSTOMER GENERATE API KEY */

app.post("/api/client/generate-key", auth, client, async (req, res) => {
  try {
    const { data: active, error: ae } = await db.from("api_keys")
      .select("id").eq("customer_id", req.user.id).eq("status", "active").limit(1);
    if (ae) throw ae;
    if (active?.length) return res.status(409).json({ success: false, message: "Active key already exists." });

    const api_key = newKey();
    const { data: key, error } = await db.from("api_keys").insert({
      customer_id: req.user.id,
      key_hash: hashKey(api_key),
      key_prefix: api_key.slice(0, 16),
      status: "active"
    }).select("id,customer_id,key_prefix,status,created_at").single();
    if (error) throw error;
    res.status(201).json({ success: true, api_key, key });
  } catch (e) { fail(res, e, "Could not generate API key."); }
});

/* CUSTOMER REVOKE API KEY */

app.post("/api/client/revoke-key/:id", auth, client, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys").update({ status: "revoked" })
      .eq("id", req.params.id).eq("customer_id", req.user.id)
      .select("id,status").maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, message: "API key not found." });
    res.json({ success: true, message: "API key revoked." });
  } catch (e) { fail(res, e, "Could not revoke API key."); }
});

/* API KEY VALIDATION */

app.post("/api/keys/validate", async (req, res) => {
  try {
    const keyValue = clean(req.body.api_key || req.headers["x-api-key"]);
    if (!keyValue) return res.status(400).json({ success: false, message: "API key required." });

    const { data, error } = await db.from("api_keys")
      .select("id,customer_id,key_prefix,status")
      .eq("key_hash", hashKey(keyValue)).maybeSingle();
    if (error) throw error;
    if (!data || data.status !== "active") {
      return res.status(401).json({ success: false, valid: false, message: "Invalid or inactive API key." });
    }
    res.json({ success: true, valid: true, customer_id: data.customer_id, key_prefix: data.key_prefix });
  } catch (e) { fail(res, e, "API key validation failed."); }
});

/* NOT FOUND */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found.",
    path: req.originalUrl
  });
});

/* ERROR HANDLER */

app.use((err, req, res, next) => {
  console.error("Application error:", err?.message || err);
  if (res.headersSent) return next(err);
  res.status(400).json({ success: false, message: err?.message || "Request failed." });
});

/* START SERVER */

app.listen(PORT, "0.0.0.0", () => {
  console.log("ADS GROWTH server running on port " + PORT);
});
