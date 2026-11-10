
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
  console.error("JWT_SECRET must be at least 32 characters.");
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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (allowed.includes(file.mimetype)) return cb(null, true);
    cb(new Error("Only JPG, PNG and WEBP images allowed."));
  }
});

function sendError(res, message, status = 400) {
  return res.status(status).json({
    success: false,
    message
  });
}

function hashKey(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function encryptionKey() {
  return crypto.createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();
}

function encryptKey(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
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

function decryptKey(value) {
  const [ivHex, tagHex, encryptedHex] = String(value).split(":");
  if (!ivHex || !tagHex || !encryptedHex) {
    throw new Error("Invalid encrypted API key.");
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

function createToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function adminAuth(req, res, next) {
  try {
    const token = getBearerToken(req);
    if (!token) return sendError(res, "Admin login required.", 401);

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin" || decoded.email !== ADMIN_EMAIL) {
      return sendError(res, "Unauthorized admin.", 403);
    }

    req.admin = decoded;
    next();
  } catch {
    return sendError(res, "Invalid or expired admin token.", 401);
  }
}

function clientAuth(req, res, next) {
  try {
    const token = getBearerToken(req);
    if (!token) return sendError(res, "Client login required.", 401);

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "client" || !decoded.id) {
      return sendError(res, "Unauthorized client.", 403);
    }

    req.client = decoded;
    next();
  } catch {
    return sendError(res, "Invalid or expired client token.", 401);
  }
}

async function getCustomerByLogin(login, password) {
  const value = String(login || "").trim();
  if (!value) return null;

  let query = db.from("customers").select("*");

  if (value.includes("@")) {
    query = query.ilike("email", value);
  } else {
    query = query.eq("phone", value);
  }

  const { data, error } = await query
    .order("created_at", { ascending: false })
    .limit(20);

  if (error) throw error;

  for (const customer of data || []) {
    if (
      customer.password_hash &&
      await bcrypt.compare(String(password), customer.password_hash)
    ) {
      return customer;
    }
  }

  return null;
}

function createCustomerKey() {
  return "ADS_" + crypto.randomBytes(32).toString("hex");
}

async function getCustomer(id) {
  const { data, error } = await db
    .from("customers")
    .select("id,name,email,phone,business_name,status")
    .eq("id", id)
    .maybeSingle();

  if (error) throw error;
  return data;
}

// HEALTH
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH AGENCY",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({ success: true, status: "healthy" });
});

// CUSTOMER REGISTRATION
app.post("/api/register", loginLimiter, async (req, res) => {
  try {
    const { name, email, phone, business_name, password } = req.body;

    if (!name || !email || !phone || !password) {
      return sendError(res, "All required fields are mandatory.");
    }

    if (String(password).length < 6) {
      return sendError(res, "Password must be at least 6 characters.");
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();

    const { data: existing, error: existingError } = await db
      .from("customers")
      .select("id")
      .or(`email.eq.${cleanEmail},phone.eq.${cleanPhone}`)
      .limit(1);

    if (existingError) throw existingError;

    if (existing && existing.length) {
      return sendError(res, "Email or phone already registered.", 409);
    }

    const password_hash = await bcrypt.hash(String(password), 12);

    const { data, error } = await db
      .from("customers")
      .insert({
        name: String(name).trim(),
        email: cleanEmail,
        phone: cleanPhone,
        business_name: business_name
          ? String(business_name).trim()
          : null,
        password_hash,
        status: "pending"
      })
      .select("id,name,email,phone,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Registration successful. Await admin approval.",
      customer: data
    });
  } catch (error) {
    console.error("Registration:", error);
    sendError(res, error.message || "Registration failed.", 500);
  }
});

// ADMIN LOGIN
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return sendError(res, "Email and password required.");
    }

    if (email !== ADMIN_EMAIL) {
      return sendError(res, "Invalid admin login details.", 401);
    }

    const { data, error } = await authClient.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.user) {
      return sendError(res, "Invalid admin login details.", 401);
    }

    const { data: adminRecord, error: adminError } = await db
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) throw adminError;

    if (!adminRecord) {
      return sendError(res, "Admin access not configured.", 403);
    }

    const token = createToken({
      role: "admin",
      email: ADMIN_EMAIL,
      user_id: data.user.id
    });

    res.json({
      success: true,
      token,
      admin: { email: ADMIN_EMAIL }
    });
  } catch (error) {
    console.error("Admin login:", error);
    sendError(res, error.message || "Admin login failed.", 500);
  }
});

app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    admin: { email: ADMIN_EMAIL }
  });
});

// CLIENT LOGIN
app.post("/api/client/login", loginLimiter, async (req, res) => {
  try {
    const login = String(
      req.body.login || req.body.email || req.body.phone || ""
    ).trim();

    const password = String(req.body.password || "");

    if (!login || !password) {
      return sendError(res, "Email/phone and password required.");
    }

    const customer = await getCustomerByLogin(login, password);

    if (!customer) {
      return sendError(res, "Invalid login details.", 401);
    }

    if (customer.status !== "approved") {
      return sendError(res, "Your account is not approved yet.", 403);
    }

    const token = createToken({
      role: "client",
      id: customer.id,
      email: customer.email
    });

    res.json({
      success: true,
      token,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
        business_name: customer.business_name,
        status: customer.status
      }
    });
  } catch (error) {
    console.error("Client login:", error);
    sendError(res, error.message || "Client login failed.", 500);
  }
});

app.get("/api/client/me", clientAuth, async (req, res) => {
  try {
    const customer = await getCustomer(req.client.id);
    if (!customer) return sendError(res, "Customer not found.", 404);
    res.json({ success: true, customer });
  } catch (error) {
    sendError(res, error.message, 500);
  }
});
// ADMIN CUSTOMERS
app.get("/api/admin/customers", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db
      .from("customers")
      .select("id,name,email,phone,business_name,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, customers: data || [] });
  } catch (error) {
    sendError(res, error.message || "Could not load customers.", 500);
  }
});

app.post("/api/admin/customers/:id/approve", adminAuth, async (req, res) => {
  try {
    const { error } = await db.from("customers")
      .update({ status: "approved" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "Customer approved." });
  } catch (error) {
    sendError(res, error.message, 500);
  }
});

app.post("/api/admin/customers/:id/reject", adminAuth, async (req, res) => {
  try {
    const { error } = await db.from("customers")
      .update({ status: "rejected" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "Customer rejected." });
  } catch (error) {
    sendError(res, error.message, 500);
  }
});

app.post("/api/admin/customers/:id/reset-password", adminAuth, async (req, res) => {
  try {
    const password = String(req.body.password || "");
    if (password.length < 6) {
      return sendError(res, "Password must be at least 6 characters.");
    }

    const password_hash = await bcrypt.hash(password, 12);

    const { data, error } = await db.from("customers")
      .update({ password_hash })
      .eq("id", req.params.id)
      .select("id,name,email")
      .single();

    if (error) throw error;
    res.json({ success: true, message: "Customer password updated.", customer: data });
  } catch (error) {
    sendError(res, error.message || "Password reset failed.", 500);
  }
});

// ADMIN PAYMENTS
app.get("/api/admin/payments", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("payments")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    const payments = (data || []).map(p => ({
      ...p,
      transaction_id: p.transaction_id || p.utr || null,
      proof_url: p.proof_url || p.screenshot_url || null
    }));

    res.json({ success: true, payments });
  } catch (error) {
    sendError(res, error.message || "Could not load payments.", 500);
  }
});

app.post("/api/admin/payments/:id/approve", adminAuth, async (req, res) => {
  try {
    const { data: payment, error: paymentError } = await db.from("payments")
      .update({ status: "approved" })
      .eq("id", req.params.id)
      .select("id,customer_id")
      .single();

    if (paymentError) throw paymentError;

    const { error: customerError } = await db.from("customers")
      .update({ status: "approved" })
      .eq("id", payment.customer_id);

    if (customerError) throw customerError;

    res.json({ success: true, message: "Payment approved and customer activated." });
  } catch (error) {
    sendError(res, error.message || "Payment approval failed.", 500);
  }
});

app.post("/api/admin/payments/:id/reject", adminAuth, async (req, res) => {
  try {
    const { error } = await db.from("payments")
      .update({ status: "rejected" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "Payment rejected." });
  } catch (error) {
    sendError(res, error.message || "Payment rejection failed.", 500);
  }
});

// ADMIN API KEY LIST - compatible with admin.html
app.get("/api/admin/keys", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys")
      .select("id,customer_id,key_prefix,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      keys: (data || []).map(k => ({
        ...k,
        name: k.name || "WhatsApp API"
      }))
    });
  } catch (error) {
    sendError(res, error.message || "Could not load API keys.", 500);
  }
});

// ADMIN GENERATE API KEY
app.post("/api/admin/keys", adminAuth, async (req, res) => {
  try {
    const customerId = String(req.body.customer_id || "").trim();
    const name = String(req.body.name || "WhatsApp API").trim();

    if (!customerId) return sendError(res, "Customer ID required.");

    const customer = await getCustomer(customerId);
    if (!customer) return sendError(res, "Customer not found.", 404);

    const apiKey = createCustomerKey();

    const { data, error } = await db.from("api_keys").insert({
      customer_id: customerId,
      name,
      key_hash: hashKey(apiKey),
      key_prefix: apiKey.slice(0, 12),
      key_encrypted: encryptKey(apiKey),
      status: "active"
    }).select("id,customer_id,key_prefix,status,created_at").single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      api_key: apiKey,
      key: apiKey,
      record: data
    });
  } catch (error) {
    sendError(res, error.message || "API key generation failed.", 500);
  }
});

// ADMIN REVEAL KEY
app.post("/api/admin/keys/:id/reveal", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys")
      .select("id,key_encrypted,status")
      .eq("id", req.params.id)
      .maybeSingle();

    if (error) throw error;
    if (!data || !data.key_encrypted) {
      return sendError(res, "API key not found.", 404);
    }
    if (data.status !== "active") {
      return sendError(res, "API key is revoked.", 400);
    }

    res.json({ success: true, key: decryptKey(data.key_encrypted) });
  } catch (error) {
    sendError(res, error.message || "Could not reveal API key.", 500);
  }
});

// ADMIN REVOKE KEY
app.post("/api/admin/keys/:id/revoke", adminAuth, async (req, res) => {
  try {
    const { error } = await db.from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "API key revoked." });
  } catch (error) {
    sendError(res, error.message || "Could not revoke API key.", 500);
  }
});

// COMPATIBILITY WITH OLDER KEY ROUTES
app.post("/api/admin/customers/:id/api-key", adminAuth, async (req, res) => {
  req.body.customer_id = req.params.id;
  req.body.name = req.body.name || "WhatsApp API";
  return app._router.handle(req, res, () => {});
});

// CLIENT API KEYS
app.get("/api/client/keys", clientAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys")
      .select("id,customer_id,key_prefix,status,created_at,name")
      .eq("customer_id", req.client.id)
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, keys: data || [] });
  } catch (error) {
    sendError(res, error.message, 500);
  }
});

app.post("/api/client/keys", clientAuth, async (req, res) => {
  try {
    const apiKey = createCustomerKey();

    const { data, error } = await db.from("api_keys").insert({
      customer_id: req.client.id,
      name: String(req.body.name || "WhatsApp API"),
      key_hash: hashKey(apiKey),
      key_prefix: apiKey.slice(0, 12),
      key_encrypted: encryptKey(apiKey),
      status: "active"
    }).select("id,customer_id,key_prefix,status,created_at,name").single();

    if (error) throw error;
    res.status(201).json({ success: true, key: apiKey, api_key: apiKey, record: data });
  } catch (error) {
    sendError(res, error.message || "Key generation failed.", 500);
  }
});

app.post("/api/client/keys/:id/reveal", clientAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("api_keys")
      .select("id,key_encrypted,status")
      .eq("id", req.params.id)
      .eq("customer_id", req.client.id)
      .maybeSingle();

    if (error) throw error;
    if (!data || !data.key_encrypted) return sendError(res, "API key not found.", 404);
    if (data.status !== "active") return sendError(res, "API key is revoked.", 400);

    res.json({ success: true, key: decryptKey(data.key_encrypted), api_key: decryptKey(data.key_encrypted) });
  } catch (error) {
    sendError(res, error.message || "Key reveal failed.", 500);
  }
});

app.post("/api/client/keys/:id/revoke", clientAuth, async (req, res) => {
  try {
    const { error } = await db.from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .eq("customer_id", req.client.id);

    if (error) throw error;
    res.json({ success: true, message: "API key revoked." });
  } catch (error) {
    sendError(res, error.message || "Key revoke failed.", 500);
  }
});
    
// PAYMENT PROOF UPLOAD - CLIENT LOGIN REQUIRED
async function uploadPaymentProof(req, res) {
  try {
    const customerId = req.client.id;
    const file = req.file;

    const amount = Number(req.body.amount || 0);
    const transactionId = String(
      req.body.transaction_id || req.body.utr || ""
    ).trim();

    if (!file || !transactionId) {
      return sendError(res, "Screenshot and transaction ID required.");
    }

    if (!Number.isFinite(amount) || amount < 0) {
      return sendError(res, "Invalid payment amount.");
    }

    const fileName = `${customerId}/${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;

    const { error: uploadError } = await db.storage
      .from("payment-proofs")
      .upload(fileName, file.buffer, {
        contentType: file.mimetype,
        upsert: false
      });

    if (uploadError) throw uploadError;

    const { data: publicData } = db.storage
      .from("payment-proofs")
      .getPublicUrl(fileName);

    const { data, error } = await db.from("payments").insert({
      customer_id: customerId,
      amount,
      utr: transactionId,
      transaction_id: transactionId,
      screenshot_url: publicData.publicUrl,
      proof_url: publicData.publicUrl,
      status: "pending"
    }).select("*").single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Payment proof submitted for approval.",
      payment: data
    });
  } catch (error) {
    console.error("Payment upload:", error);
    sendError(res, error.message || "Payment upload failed.", 500);
  }
}

app.post(
  "/api/payment/upload",
  clientAuth,
  upload.single("proof"),
  uploadPaymentProof
);

app.post(
  "/api/payments/upload",
  clientAuth,
  upload.single("proof"),
  uploadPaymentProof
);

// CLIENT PAYMENT HISTORY
app.get("/api/client/payments", clientAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("payments")
      .select("*")
      .eq("customer_id", req.client.id)
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, payments: data || [] });
  } catch (error) {
    sendError(res, error.message, 500);
  }
});

// WHATSAPP CLOUD API CONFIGURATION
function whatsappConfig() {
  return {
    token: process.env.WHATSAPP_TOKEN,
    phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID,
    apiVersion: process.env.WHATSAPP_API_VERSION || "v23.0"
  };
}

async function whatsappRequest(path, body) {
  const config = whatsappConfig();

  if (!config.token || !config.phoneNumberId) {
    throw new Error("WhatsApp Cloud API credentials are not configured.");
  }

  const response = await fetch(
    `https://graph.facebook.com/${config.apiVersion}/${path}`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      result.error?.message || "WhatsApp API request failed."
    );
  }

  return result;
}

// SEND WHATSAPP TEXT MESSAGE
app.post("/api/whatsapp/send", clientAuth, async (req, res) => {
  try {
    const to = String(req.body.to || "").replace(/\D/g, "");
    const message = String(req.body.message || "").trim();

    if (!to || !message) {
      return sendError(res, "Recipient number and message required.");
    }

    const config = whatsappConfig();

    const result = await whatsappRequest(
      `${config.phoneNumberId}/messages`,
      {
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to,
        type: "text",
        text: { preview_url: false, body: message }
      }
    );

    res.json({ success: true, result });
  } catch (error) {
    sendError(res, error.message, 400);
  }
});

// SEND APPROVED WHATSAPP TEMPLATE
app.post("/api/whatsapp/template", clientAuth, async (req, res) => {
  try {
    const to = String(req.body.to || "").replace(/\D/g, "");
    const templateName = String(req.body.template_name || "").trim();
    const language = String(req.body.language || "en_US");

    if (!to || !templateName) {
      return sendError(res, "Recipient and template name required.");
    }

    const config = whatsappConfig();

    const result = await whatsappRequest(
      `${config.phoneNumberId}/messages`,
      {
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: {
          name: templateName,
          language: { code: language }
        }
      }
    );

    res.json({ success: true, result });
  } catch (error) {
    sendError(res, error.message, 400);
  }
});

// CAMPAIGN LIST
app.get("/api/client/campaigns", clientAuth, async (req, res) => {
  try {
    const { data, error } = await db.from("campaigns")
      .select("*")
      .eq("customer_id", req.client.id)
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, campaigns: data || [] });
  } catch (error) {
    sendError(res, error.message || "Campaign table setup required.", 500);
  }
});

// CREATE CAMPAIGN
app.post("/api/client/campaigns", clientAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const message = String(req.body.message || "").trim();
    const scheduledAt = req.body.scheduled_at || null;

    if (!name || !message) {
      return sendError(res, "Campaign name and message required.");
    }

    const { data, error } = await db.from("campaigns").insert({
      customer_id: req.client.id,
      name,
      message,
      scheduled_at: scheduledAt,
      status: scheduledAt ? "scheduled" : "draft"
    }).select("*").single();

    if (error) throw error;
    res.status(201).json({ success: true, campaign: data });
  } catch (error) {
    sendError(res, error.message || "Campaign creation failed.", 500);
  }
});

// WHATSAPP WEBHOOK VERIFICATION
app.get("/api/whatsapp/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    token &&
    token === process.env.WHATSAPP_VERIFY_TOKEN
  ) {
    return res.status(200).send(challenge);
  }

  return res.sendStatus(403);
});

// WHATSAPP WEBHOOK EVENTS
app.post("/api/whatsapp/webhook", (req, res) => {
  try {
    const body = req.body;

    if (body.object === "whatsapp_business_account") {
      for (const entry of body.entry || []) {
        for (const change of entry.changes || []) {
          const value = change.value || {};

          console.log("WhatsApp webhook event:", JSON.stringify({
            messages: value.messages || [],
            statuses: value.statuses || []
          }));
        }
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("Webhook error:", error);
    res.sendStatus(500);
  }
});

// API KEY VALIDATION
app.post("/api/keys/validate", async (req, res) => {
  try {
    const apiKey = String(req.body.api_key || req.body.key || "");

    if (!apiKey) return sendError(res, "API key required.", 401);

    const { data, error } = await db.from("api_keys")
      .select("id,customer_id,status")
      .eq("key_hash", hashKey(apiKey))
      .maybeSingle();

    if (error) throw error;

    if (!data || data.status !== "active") {
      return sendError(res, "Invalid or revoked API key.", 401);
    }

    res.json({
      success: true,
      valid: true,
      customer_id: data.customer_id
    });
  } catch (error) {
    sendError(res, error.message || "Key validation failed.", 500);
  }
});

// UNKNOWN API ROUTE
app.use("/api", (req, res) => {
  sendError(res, "API route not found.", 404);
});

// GENERAL ERROR HANDLER
app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) return next(error);

  sendError(
    res,
    error.message || "Internal server error.",
    error.status || 500
  );
});

app.listen(PORT, () => {
  console.log(`ADS GROWTH AGENCY running on port ${PORT}`);
});
  
