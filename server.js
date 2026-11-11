
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
const ADMIN_EMAIL = "sainiatul041@gmail.com";
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v23.0";

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SUPABASE_ANON_KEY",
  "JWT_SECRET"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must contain at least 32 characters.");
  process.exit(1);
}

const db = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const authClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (allowed.includes(file.mimetype)) {
      return cb(null, true);
    }
    cb(new Error("Only JPG, PNG and WEBP files are allowed."));
  }
});

function fail(res, message, status = 400) {
  return res.status(status).json({
    success: false,
    message
  });
}

function asyncRoute(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });
}

function bearer(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ")
    ? header.slice(7)
    : "";
}

function hash(value) {
  return crypto.createHash("sha256")
    .update(value)
    .digest("hex");
}

function encryptionKey() {
  return crypto.createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return [
    iv.toString("hex"),
    cipher.getAuthTag().toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decrypt(value) {
  const [ivHex, tagHex, encryptedHex] =
    String(value || "").split(":");

  if (!ivHex || !tagHex || !encryptedHex) {
    throw new Error("Invalid encrypted value.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(ivHex, "hex")
  );

  decipher.setAuthTag(Buffer.from(tagHex, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, "hex")),
    decipher.final()
  ]).toString("utf8");
}

function adminAuth(req, res, next) {
  try {
    const decoded = jwt.verify(
      bearer(req),
      process.env.JWT_SECRET
    );

    if (
      decoded.role !== "admin" ||
      decoded.email !== ADMIN_EMAIL
    ) {
      return fail(res, "Unauthorized admin.", 403);
    }

    req.admin = decoded;
    next();
  } catch {
    return fail(res, "Admin login required or token expired.", 401);
  }
}

function clientAuth(req, res, next) {
  try {
    const decoded = jwt.verify(
      bearer(req),
      process.env.JWT_SECRET
    );

    if (decoded.role !== "client" || !decoded.id) {
      return fail(res, "Unauthorized client.", 403);
    }

    req.client = decoded;
    next();
  } catch {
    return fail(res, "Client login required or token expired.", 401);
  }
}

async function approvedCustomer(req, res, next) {
  try {
    const { data, error } = await db
      .from("customers")
      .select("id,status")
      .eq("id", req.client.id)
      .maybeSingle();

    if (error) throw error;
    if (!data) return fail(res, "Customer not found.", 404);

    if (data.status !== "approved") {
      return fail(res, "Your account is not approved.", 403);
    }

    next();
  } catch (error) {
    next(error);
  }
}

async function getCustomerByLogin(login, password) {
  const value = String(login || "").trim();

  let query = db.from("customers").select("*");

  query = value.includes("@")
    ? query.ilike("email", value)
    : query.eq("phone", value);

  const { data, error } = await query.limit(20);

  if (error) throw error;

  for (const customer of data || []) {
    if (
      customer.password_hash &&
      await bcrypt.compare(
        String(password),
        customer.password_hash
      )
    ) {
      return customer;
    }
  }

  return null;
}

async function getCustomer(id) {
  const { data, error } = await db
    .from("customers")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) throw error;
  return data;
}

async function getWhatsAppAccount(customerId) {
  const { data, error } = await db
    .from("whatsapp_accounts")
    .select("*")
    .eq("customer_id", customerId)
    .eq("status", "connected")
    .maybeSingle();

  if (error) throw error;
  return data;
}

async function graphRequest(path, options = {}) {
  const response = await fetch(
    `https://graph.facebook.com/${GRAPH_VERSION}/${path}`,
    options
  );

  const body = await response.json();

  if (!response.ok) {
    throw new Error(
      body.error?.message || "Meta Graph API request failed."
    );
  }

  return body;
}

function newApiKey() {
  return "ADS_" + crypto.randomBytes(32).toString("hex");
}

// HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH AGENCY",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy"
  });
});

// CUSTOMER REGISTRATION
app.post("/api/register", limiter, asyncRoute(async (req, res) => {
  const {
    name,
    email,
    phone,
    business_name,
    password
  } = req.body;

  if (!name || !email || !phone || !password) {
    return fail(
      res,
      "Name, email, phone and password are required."
    );
  }

  if (String(password).length < 6) {
    return fail(res, "Password must be at least 6 characters.");
  }

  const cleanName = String(name).trim();
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanPhone = String(phone).trim();

  const { data: existing, error: checkError } = await db
    .from("customers")
    .select("id")
    .or(`email.eq.${cleanEmail},phone.eq.${cleanPhone}`)
    .limit(1);

  if (checkError) throw checkError;

  if (existing && existing.length) {
    return fail(res, "Email or phone already registered.", 409);
  }

  const password_hash = await bcrypt.hash(
    String(password),
    12
  );

  const { data, error } = await db
    .from("customers")
    .insert({
      name: cleanName,
      full_name: cleanName,
      email: cleanEmail,
      phone: cleanPhone,
      business_name: business_name
        ? String(business_name).trim()
        : null,
      password_hash,
      plan: "Business",
      amount: 7999,
      status: "pending"
    })
    .select("*")
    .single();

  if (error) throw error;

  res.status(201).json({
    success: true,
    message: "Registration successful. Await admin approval.",
    customer: data
  });
}));

// ADMIN LOGIN
app.post("/api/admin/login", limiter, asyncRoute(async (req, res) => {
  const email = String(req.body.email || "")
    .trim()
    .toLowerCase();

  const password = String(req.body.password || "");

  if (!email || !password) {
    return fail(res, "Email and password required.");
  }

  if (email !== ADMIN_EMAIL) {
    return fail(res, "Invalid admin login details.", 401);
  }

  const { data, error } =
    await authClient.auth.signInWithPassword({
      email,
      password
    });

  if (error || !data.user) {
    return fail(res, "Invalid admin login details.", 401);
  }

  const { data: record, error: adminError } = await db
    .from("admin_users")
    .select("user_id")
    .eq("user_id", data.user.id)
    .maybeSingle();

  if (adminError) throw adminError;

  if (!record) {
    return fail(res, "Admin access not configured.", 403);
  }

  const token = signToken({
    role: "admin",
    email: ADMIN_EMAIL,
    user_id: data.user.id
  });

  res.json({
    success: true,
    token,
    admin: { email: ADMIN_EMAIL }
  });
}));

app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    admin: { email: ADMIN_EMAIL }
  });
});

// CLIENT LOGIN
app.post("/api/client/login", limiter, asyncRoute(async (req, res) => {
  const login = String(
    req.body.login ||
    req.body.email ||
    req.body.phone ||
    ""
  ).trim();

  const password = String(req.body.password || "");

  if (!login || !password) {
    return fail(res, "Email/phone and password required.");
  }

  const customer = await getCustomerByLogin(login, password);

  if (!customer) {
    return fail(res, "Invalid login details.", 401);
  }

  if (customer.status !== "approved") {
    return fail(res, "Your account is not approved yet.", 403);
  }

  const token = signToken({
    role: "client",
    id: customer.id,
    email: customer.email
  });

  res.json({
    success: true,
    token,
    customer: {
      id: customer.id,
      name: customer.full_name || customer.name,
      email: customer.email,
      phone: customer.phone,
      business_name: customer.business_name,
      plan: customer.plan,
      amount: customer.amount,
      status: customer.status
    }
  });
}));

app.get("/api/client/me", clientAuth, asyncRoute(async (req, res) => {
  const customer = await getCustomer(req.client.id);

  if (!customer) {
    return fail(res, "Customer not found.", 404);
  }

  res.json({
    success: true,
    customer
  });
}));

// PART 1 ENDS HERE.
// Do not add app.listen() here.
// Continue with PART 2 below.
// ===============================
// PART 2: ADMIN, CLIENTS & API KEYS
// ===============================

const PART2_ADMIN_EMAIL = "sainiatul041@gmail.com";

// Verify admin token
async function part2AdminAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    if (!token) {
      return res.status(401).json({ success: false, message: "Admin login required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (
      decoded.role !== "admin" ||
      String(decoded.email || "").toLowerCase() !== PART2_ADMIN_EMAIL
    ) {
      return res.status(403).json({ success: false, message: "Admin access denied" });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired admin token" });
  }
}

// Verify client token
async function part2ClientAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    if (!token) {
      return res.status(401).json({ success: false, message: "Client login required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "client") {
      return res.status(403).json({ success: false, message: "Client access denied" });
    }

    const customerId = decoded.id || decoded.customer_id || decoded.sub;

    if (!customerId) {
      return res.status(401).json({ success: false, message: "Invalid client token" });
    }

    req.customerId = customerId;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired client token" });
  }
}

// Encrypt API keys before saving them
function part2EncryptApiKey(value) {
  const secret = crypto
    .createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", secret, iv);

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    tag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

// Admin dashboard summary
app.get("/api/admin/dashboard", part2AdminAuth, async (req, res) => {
  try {
    const { data: customers, error } = await supabaseAdmin
      .from("customers")
      .select("id,status,amount,created_at");

    if (error) throw error;

    const rows = customers || [];

    return res.json({
      success: true,
      total_clients: rows.length,
      approved_clients: rows.filter(x => x.status === "approved").length,
      pending_clients: rows.filter(x => x.status === "pending").length,
      rejected_clients: rows.filter(x => x.status === "rejected").length,
      total_amount: rows.reduce((sum, x) => sum + Number(x.amount || 0), 0)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Dashboard load failed"
    });
  }
});

// Admin: list all clients
app.get("/api/admin/clients", part2AdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("customers")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    // Never send password hashes to the browser
    const safeClients = (data || []).map(client => {
      const { password_hash, password, ...safe } = client;
      return safe;
    });

    return res.json({ success: true, clients: safeClients });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Could not load clients"
    });
  }
});

// Admin: approve, reject or suspend a client
app.patch("/api/admin/clients/:id/status", part2AdminAuth, async (req, res) => {
  try {
    const allowed = ["pending", "approved", "rejected", "suspended"];
    const status = String(req.body.status || "").toLowerCase();

    if (!allowed.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be pending, approved, rejected or suspended"
      });
    }

    const { data, error } = await supabaseAdmin
      .from("customers")
      .update({ status })
      .eq("id", req.params.id)
      .select("id,name,full_name,email,status")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "Client status updated",
      client: data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Status update failed"
    });
  }
});

// Admin: update client plan
app.patch("/api/admin/clients/:id/plan", part2AdminAuth, async (req, res) => {
  try {
    const plan = String(req.body.plan || "").trim();

    if (!plan || plan.length > 50) {
      return res.status(400).json({ success: false, message: "Valid plan required" });
    }

    const { data, error } = await supabaseAdmin
      .from("customers")
      .update({ plan })
      .eq("id", req.params.id)
      .select("id,name,full_name,email,plan")
      .single();

    if (error) throw error;

    return res.json({ success: true, client: data });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Plan update failed"
    });
  }
});

// Client: create an API key
app.post("/api/client/api-keys", part2ClientAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "WhatsApp API").trim().slice(0, 80);

    const rawKey = "ag_" + crypto.randomBytes(32).toString("hex");
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const encryptedKey = part2EncryptApiKey(rawKey);
    const keyPrefix = rawKey.slice(0, 10);

    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .insert({
        customer_id: req.customerId,
        name,
        key_encrypted: encryptedKey,
        key_hash: keyHash,
        key_prefix: keyPrefix,
        status: "active"
      })
      .select("id,name,key_prefix,status,created_at")
      .single();

    if (error) throw error;

    // Show the full key only once
    return res.status(201).json({
      success: true,
      message: "API key created. Copy and save it now; it will not be shown again.",
      api_key: rawKey,
      record: data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "API key creation failed"
    });
  }
});

// Client: list own API keys
app.get("/api/client/api-keys", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("customer_id", req.customerId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({ success: true, api_keys: data || [] });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Could not load API keys"
    });
  }
});

// Client: revoke own API key
app.patch("/api/client/api-keys/:id/revoke", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .eq("customer_id", req.customerId)
      .select("id,status")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "API key revoked",
      api_key: data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "API key revoke failed"
    });
  }
});

// PART 2 ENDS HERE.
// Paste PART 3 directly below this section.
// Do not add app.listen() yet.
      
// ===============================
// PART 3: WHATSAPP & CAMPAIGNS
// ===============================

// Decrypt an encrypted WhatsApp access token
function part3DecryptApiKey(value) {
  const parts = String(value || "").split(":");

  if (parts.length !== 3) {
    throw new Error("Saved access token is invalid");
  }

  const secret = crypto
    .createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();

  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const encrypted = Buffer.from(parts[2], "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", secret, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

// WhatsApp Graph API request
async function part3WhatsAppRequest(phoneNumberId, accessToken, payload) {
  const version = process.env.GRAPH_API_VERSION || "v23.0";
  const url =
    `https://graph.facebook.com/${version}/${encodeURIComponent(phoneNumberId)}/messages`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      result.error?.message ||
      result.error?.error_user_msg ||
      "WhatsApp message sending failed";

    throw new Error(message);
  }

  return result;
}

// Get a client's WhatsApp connection
async function part3GetConnection(customerId) {
  const { data, error } = await supabaseAdmin
    .from("whatsapp_connections")
    .select("id,customer_id,phone_number_id,business_account_id,access_token_encrypted,status")
    .eq("customer_id", customerId)
    .maybeSingle();

  if (error) throw error;
  if (!data || data.status !== "connected") {
    throw new Error("WhatsApp account is not connected");
  }

  return {
    ...data,
    access_token: part3DecryptApiKey(data.access_token_encrypted)
  };
}

// Client: save WhatsApp Cloud API connection
app.post("/api/client/whatsapp/connect", part2ClientAuth, async (req, res) => {
  try {
    const phoneNumberId = String(req.body.phone_number_id || "").trim();
    const businessAccountId = String(req.body.business_account_id || "").trim();
    const accessToken = String(req.body.access_token || "").trim();

    if (!phoneNumberId || !accessToken) {
      return res.status(400).json({
        success: false,
        message: "Phone Number ID and Access Token are required"
      });
    }

    if (phoneNumberId.length > 100 || accessToken.length > 5000) {
      return res.status(400).json({
        success: false,
        message: "Invalid WhatsApp connection details"
      });
    }

    // Verify credentials with Meta before saving
    const version = process.env.GRAPH_API_VERSION || "v23.0";
    const verifyUrl =
      `https://graph.facebook.com/${version}/${encodeURIComponent(phoneNumberId)}` +
      `?fields=id,display_phone_number,verified_name`;

    const verifyResponse = await fetch(verifyUrl, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const verifyData = await verifyResponse.json().catch(() => ({}));

    if (!verifyResponse.ok) {
      return res.status(400).json({
        success: false,
        message: verifyData.error?.message || "Meta credentials could not be verified"
      });
    }

    const encryptedToken = part2EncryptApiKey(accessToken);

    const { data, error } = await supabaseAdmin
      .from("whatsapp_connections")
      .upsert({
        customer_id: req.customerId,
        phone_number_id: phoneNumberId,
        business_account_id: businessAccountId || null,
        access_token_encrypted: encryptedToken,
        status: "connected",
        updated_at: new Date().toISOString()
      }, { onConflict: "customer_id" })
      .select("id,phone_number_id,business_account_id,status,updated_at")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "WhatsApp account connected",
      connection: data,
      meta: {
        display_phone_number: verifyData.display_phone_number || null,
        verified_name: verifyData.verified_name || null
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "WhatsApp connection failed"
    });
  }
});

// Client: check WhatsApp connection
app.get("/api/client/whatsapp/connection", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("whatsapp_connections")
      .select("id,phone_number_id,business_account_id,status,updated_at")
      .eq("customer_id", req.customerId)
      .maybeSingle();

    if (error) throw error;

    return res.json({
      success: true,
      connected: Boolean(data && data.status === "connected"),
      connection: data || null
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Connection status failed"
    });
  }
});

// Client: disconnect WhatsApp account
app.delete("/api/client/whatsapp/connection", part2ClientAuth, async (req, res) => {
  try {
    const { error } = await supabaseAdmin
      .from("whatsapp_connections")
      .update({ status: "disconnected" })
      .eq("customer_id", req.customerId);

    if (error) throw error;

    return res.json({ success: true, message: "WhatsApp disconnected" });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Disconnect failed"
    });
  }
});

// Client: send a WhatsApp text message
app.post("/api/client/whatsapp/send", part2ClientAuth, async (req, res) => {
  try {
    const to = String(req.body.to || "").replace(/[^\d]/g, "");
    const message = String(req.body.message || "").trim();

    if (!to || to.length < 8 || to.length > 15) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid recipient number with country code"
      });
    }

    if (!message || message.length > 4096) {
      return res.status(400).json({
        success: false,
        message: "Message must be between 1 and 4096 characters"
      });
    }

    const connection = await part3GetConnection(req.customerId);

    const result = await part3WhatsAppRequest(
      connection.phone_number_id,
      connection.access_token,
      {
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to,
        type: "text",
        text: {
          preview_url: false,
          body: message
        }
      }
    );

    return res.json({
      success: true,
      message: "Message accepted by WhatsApp",
      whatsapp_response: result
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message || "Message sending failed"
    });
  }
});

// Client: create a campaign draft
app.post("/api/client/campaigns", part2ClientAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const message = String(req.body.message || "").trim();
    const recipients = req.body.recipients;

    if (!name || !message || !Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Campaign name, message and recipient numbers are required"
      });
    }

    if (name.length > 100 || message.length > 4096 || recipients.length > 1000) {
      return res.status(400).json({
        success: false,
        message: "Campaign details exceed allowed limits"
      });
    }

    const cleanRecipients = [...new Set(
      recipients
        .map(number => String(number).replace(/[^\d]/g, ""))
        .filter(number => number.length >= 8 && number.length <= 15)
    )];

    if (!cleanRecipients.length) {
      return res.status(400).json({
        success: false,
        message: "No valid recipient numbers found"
      });
    }

    const { data, error } = await supabaseAdmin
      .from("campaigns")
      .insert({
        customer_id: req.customerId,
        name,
        message,
        recipients: cleanRecipients,
        status: "draft",
        sent_count: 0,
        failed_count: 0
      })
      .select("*")
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      message: "Campaign draft created",
      campaign: data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Campaign creation failed"
    });
  }
});

// Client: list own campaigns
app.get("/api/client/campaigns", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("campaigns")
      .select("*")
      .eq("customer_id", req.customerId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({ success: true, campaigns: data || [] });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Could not load campaigns"
    });
  }
});

// Client: send a saved campaign immediately
app.post("/api/client/campaigns/:id/send", part2ClientAuth, async (req, res) => {
  try {
    const { data: campaign, error: campaignError } = await supabaseAdmin
      .from("campaigns")
      .select("*")
      .eq("id", req.params.id)
      .eq("customer_id", req.customerId)
      .single();

    if (campaignError) throw campaignError;

    if (campaign.status === "sending" || campaign.status === "sent") {
      return res.status(409).json({
        success: false,
        message: "Campaign is already sending or has been sent"
      });
    }

    const recipients = Array.isArray(campaign.recipients)
      ? campaign.recipients
      : [];

    if (!recipients.length) {
      return res.status(400).json({
        success: false,
        message: "Campaign has no recipients"
      });
    }

    const connection = await part3GetConnection(req.customerId);

    await supabaseAdmin
      .from("campaigns")
      .update({ status: "sending" })
      .eq("id", campaign.id)
      .eq("customer_id", req.customerId);

    let sentCount = 0;
    let failedCount = 0;
    const errors = [];

    // Send one by one to avoid a sudden burst of requests
    for (const recipient of recipients) {
      try {
        await part3WhatsAppRequest(
          connection.phone_number_id,
          connection.access_token,
          {
            messaging_product: "whatsapp",
            recipient_type: "individual",
            to: recipient,
            type: "text",
            text: {
              preview_url: false,
              body: campaign.message
            }
          }
        );

        sentCount++;
      } catch (sendError) {
        failedCount++;

        if (errors.length < 10) {
          errors.push({
            recipient,
            error: sendError.message
          });
        }
      }
    }

    const finalStatus = failedCount === 0
      ? "sent"
      : sentCount === 0
        ? "failed"
        : "partially_sent";

    const { error: updateError } = await supabaseAdmin
      .from("campaigns")
      .update({
        status: finalStatus,
        sent_count: sentCount,
        failed_count: failedCount
      })
      .eq("id", campaign.id)
      .eq("customer_id", req.customerId);

    if (updateError) throw updateError;

    return res.json({
      success: true,
      message: "Campaign sending finished",
      status: finalStatus,
      total_recipients: recipients.length,
      sent_count: sentCount,
      failed_count: failedCount,
      errors
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message || "Campaign sending failed"
    });
  }
});

// PART 3 ENDS HERE.
// Paste PART 4 directly below this section.
// Do not add app.listen() yet.
 
// ===============================
// PART 4: PAYMENTS, WEBHOOKS & REPORTS
// ===============================

// Payment proof upload: image only, maximum 5 MB
const part4Upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and WEBP images are allowed"));
    }

    cb(null, true);
  }
});

// Client: submit payment proof
app.post(
  "/api/client/payments",
  part2ClientAuth,
  part4Upload.single("proof"),
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);
      const transactionId = String(req.body.transaction_id || "").trim();

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid payment amount"
        });
      }

      if (!transactionId || transactionId.length > 150) {
        return res.status(400).json({
          success: false,
          message: "Valid transaction ID is required"
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "Payment screenshot is required"
        });
      }

      const extension = req.file.mimetype === "image/png"
        ? "png"
        : req.file.mimetype === "image/webp"
          ? "webp"
          : "jpg";

      const filePath =
        `${req.customerId}/${Date.now()}-${crypto.randomBytes(5).toString("hex")}.${extension}`;

      const { error: uploadError } = await supabaseAdmin.storage
        .from("payment-proofs")
        .upload(filePath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;

      const { data: urlData } = supabaseAdmin.storage
        .from("payment-proofs")
        .getPublicUrl(filePath);

      const proofUrl = urlData.publicUrl;

      const { data, error } = await supabaseAdmin
        .from("payments")
        .insert({
          customer_id: req.customerId,
          amount,
          transaction_id: transactionId,
          proof_url: proofUrl,
          status: "pending"
        })
        .select("id,amount,transaction_id,proof_url,status,created_at")
        .single();

      if (error) throw error;

      return res.status(201).json({
        success: true,
        message: "Payment proof submitted for admin review",
        payment: data
      });
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: error.message || "Payment submission failed"
      });
    }
  }
);

// Client: payment history
app.get("/api/client/payments", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("payments")
      .select("id,amount,transaction_id,proof_url,status,created_at")
      .eq("customer_id", req.customerId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({ success: true, payments: data || [] });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Payment history failed"
    });
  }
});

// Admin: view all payment submissions
app.get("/api/admin/payments", part2AdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("payments")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({ success: true, payments: data || [] });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Could not load payments"
    });
  }
});

// Admin: approve or reject a payment
app.patch("/api/admin/payments/:id/status", part2AdminAuth, async (req, res) => {
  try {
    const status = String(req.body.status || "").toLowerCase();

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be approved or rejected"
      });
    }

    const { data, error } = await supabaseAdmin
      .from("payments")
      .update({ status })
      .eq("id", req.params.id)
      .select("id,customer_id,amount,status")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "Payment status updated",
      payment: data
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Payment status update failed"
    });
  }
});

// Client: campaign report
app.get("/api/client/reports", part2ClientAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("campaigns")
      .select("id,name,status,sent_count,failed_count,created_at")
      .eq("customer_id", req.customerId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    const campaigns = data || [];

    const totals = campaigns.reduce((result, campaign) => {
      result.sent += Number(campaign.sent_count || 0);
      result.failed += Number(campaign.failed_count || 0);
      return result;
    }, { sent: 0, failed: 0 });

    return res.json({
      success: true,
      campaign_count: campaigns.length,
      total_sent: totals.sent,
      total_failed: totals.failed,
      campaigns
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Report loading failed"
    });
  }
});

// Admin: basic campaign report
app.get("/api/admin/reports", part2AdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("campaigns")
      .select("id,customer_id,name,status,sent_count,failed_count,created_at");

    if (error) throw error;

    const campaigns = data || [];

    const totals = campaigns.reduce((result, campaign) => {
      result.sent += Number(campaign.sent_count || 0);
      result.failed += Number(campaign.failed_count || 0);
      return result;
    }, { sent: 0, failed: 0 });

    return res.json({
      success: true,
      campaign_count: campaigns.length,
      total_sent: totals.sent,
      total_failed: totals.failed,
      campaigns
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Admin report failed"
    });
  }
});

// ===============================
// WHATSAPP WEBHOOK VERIFICATION
// ===============================

// Set WHATSAPP_VERIFY_TOKEN in Render environment variables
app.get("/webhook/whatsapp", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    token &&
    process.env.WHATSAPP_VERIFY_TOKEN &&
    token === process.env.WHATSAPP_VERIFY_TOKEN
  ) {
    return res.status(200).send(String(challenge || ""));
  }

  return res.sendStatus(403);
});

// Receive WhatsApp messages and delivery status updates
app.post("/webhook/whatsapp", async (req, res) => {
  try {
    const body = req.body || {};

    if (body.object !== "whatsapp_business_account") {
      return res.sendStatus(404);
    }

    // Acknowledge Meta's webhook request
    res.sendStatus(200);

    for (const entry of body.entry || []) {
      for (const change of entry.changes || []) {
        const value = change.value || {};
        const metadata = value.metadata || {};
        const phoneNumberId = metadata.phone_number_id;

        if (!phoneNumberId) continue;

        const { data: connection, error: connectionError } =
          await supabaseAdmin
            .from("whatsapp_connections")
            .select("customer_id")
            .eq("phone_number_id", phoneNumberId)
            .maybeSingle();

        if (connectionError || !connection) continue;

        const customerId = connection.customer_id;

        // Incoming messages
        for (const message of value.messages || []) {
          const messageText =
            message.text?.body ||
            message.button?.text ||
            message.interactive?.button_reply?.title ||
            message.interactive?.list_reply?.title ||
            "";

          await supabaseAdmin
            .from("whatsapp_messages")
            .insert({
              customer_id: customerId,
              wa_message_id: message.id,
              recipient: message.from || "",
              direction: "incoming",
              message_type: message.type || "unknown",
              message_text: messageText,
              status: "received",
              message_timestamp: message.timestamp
                ? new Date(Number(message.timestamp) * 1000).toISOString()
                : new Date().toISOString()
            });
        }

        // Delivery, read and failure status updates
        for (const statusItem of value.statuses || []) {
          await supabaseAdmin
            .from("whatsapp_messages")
            .update({
              status: statusItem.status || "unknown",
              status_timestamp: statusItem.timestamp
                ? new Date(Number(statusItem.timestamp) * 1000).toISOString()
                : new Date().toISOString()
            })
            .eq("customer_id", customerId)
            .eq("wa_message_id", statusItem.id);
        }
      }
    }
  } catch (error) {
    console.error("WhatsApp webhook processing error:", error.message);
  }
});

// Client: view WhatsApp message history
app.get("/api/client/whatsapp/messages", part2ClientAuth, async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(parseInt(req.query.limit || "50", 10) || 50, 1),
      100
    );

    const { data, error } = await supabaseAdmin
      .from("whatsapp_messages")
      .select("*")
      .eq("customer_id", req.customerId)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) throw error;

    return res.json({ success: true, messages: data || [] });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Message history failed"
    });
  }
});

// ===============================
// FINAL ERROR HANDLERS & SERVER
// ===============================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found",
    path: req.path
  });
});

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (res.headersSent) return next(error);

  res.status(error.status || 500).json({
    success: false,
    message: error.message || "Internal server error"
  });
});

app.listen(PORT, () => {
  console.log(`ADS GROWTH AGENCY server running on port ${PORT}`);
});

// ===============================
// END OF SERVER.JS
// ===============================
  
