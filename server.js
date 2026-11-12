
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
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v23.0";

const FRONTEND_URL = process.env.FRONTEND_URL ||
"https://sainiatul041-source.github.io/Ads-growth-whatsapp-api";

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
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
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.set("trust proxy", 1);

app.use(helmet({
  crossOriginResourcePolicy: {
    policy: "cross-origin"
  }
}));

app.use(cors({
  origin(origin, callback) {
    const allowed = [
      FRONTEND_URL,
      "https://sainiatul041-source.github.io",
      "http://localhost:3000",
      "http://127.0.0.1:5500"
    ];

    if (!origin || allowed.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"]
}));

// Meta webhook raw body must be preserved.
app.use(
  "/webhook/meta",
  express.raw({
    type: "application/json",
    limit: "2mb"
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter(req, file, cb) {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "application/pdf"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG, WEBP or PDF files are allowed."));
    }

    cb(null, true);
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function asyncRoute(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function safeString(value, max = 200) {
  return String(value || "").trim().slice(0, max);
}

function makeJwt(payload) {
  return jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function verifyJwt(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

function getBearer(req) {
  const header = req.headers.authorization || "";

  return header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";
}

function clientAuth(req, res, next) {
  try {
    const decoded = verifyJwt(getBearer(req));

    if (decoded.role !== "client" || !decoded.id) {
      return res.status(401).json({
        success: false,
        message: "Invalid client token."
      });
    }

    req.client = decoded;
    next();

  } catch {
    return res.status(401).json({
      success: false,
      message: "Please login again."
    });
  }
}

function adminAuth(req, res, next) {
  try {
    const decoded = verifyJwt(getBearer(req));

    if (
      decoded.role !== "admin" ||
      String(decoded.email || "").toLowerCase() !== ADMIN_EMAIL
    ) {
      return res.status(401).json({
        success: false,
        message: "Admin access denied."
      });
    }

    req.admin = decoded;
    next();

  } catch {
    return res.status(401).json({
      success: false,
      message: "Admin login required."
    });
  }
}

async function approvedCustomer(req, res, next) {
  const { data, error } = await db
    .from("customers")
    .select("id,name,full_name,email,phone,business_name,plan,amount,status")
    .eq("id", req.client.id)
    .maybeSingle();

  if (error) throw error;

  if (!data || data.status !== "approved") {
    return res.status(403).json({
      success: false,
      message: "Your account is not approved yet."
    });
  }

  req.customer = data;
  next();
}

// AES-256-GCM encryption.
// IMPORTANT: Do not change the existing JWT_SECRET.
function encryptionKey() {
  return crypto.createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();
}

function encryptSecret(value) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(String(value), "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [iv, tag, encrypted]
    .map(x => x.toString("base64"))
    .join(".");
}

function decryptSecret(value) {
  const parts = String(value || "").split(".");

  if (parts.length !== 3) {
    throw new Error("Encrypted value is invalid.");
  }

  const [iv, tag, encrypted] = parts.map(
    x => Buffer.from(x, "base64")
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

function hashApiKey(key) {
  return crypto.createHash("sha256")
    .update(key)
    .digest("hex");
}

function constantTimeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

// HOME
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH AGENCY",
    status: "running",
    version: "2.0.0"
  });
});

// HEALTH
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH AGENCY",
    status: "running"
  });
});

// CLIENT REGISTRATION
app.post(
  "/api/register",
  authLimiter,
  asyncRoute(async (req, res) => {

    const name = safeString(
      req.body.name || req.body.full_name,
      100
    );

    const email = safeString(req.body.email, 150).toLowerCase();
    const phone = safeString(req.body.phone, 30);

    const businessName = safeString(
      req.body.business_name || name,
      120
    );

    const password = String(req.body.password || "");
    const plan = safeString(req.body.plan || "starter", 40);
    const amount = Number(req.body.amount || 4999);

    if (!name || !email || !phone || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Name, email, phone and password (minimum 8 characters) are required."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email."
      });
    }

    if (![4999, 7999, 9999].includes(amount)) {
      return res.status(400).json({
        success: false,
        message: "Invalid plan amount."
      });
    }

    const { data: existing, error: findError } = await db
      .from("customers")
      .select("id")
      .eq("email", email)
      .maybeSingle();

    if (findError) throw findError;

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Email already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data, error } = await db
      .from("customers")
      .insert({
        name,
        full_name: name,
        email,
        phone,
        business_name: businessName,
        plan,
        amount,
        password_hash: passwordHash,
        status: "pending"
      })
      .select("id,name,full_name,email,phone,business_name,plan,amount,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Registration successful. Please submit your payment.",
      customer: data
    });
  })
);

// CLIENT LOGIN
app.post(
  "/api/client/login",
  authLimiter,
  asyncRoute(async (req, res) => {

    const email = safeString(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    const { data: customer, error } = await db
      .from("customers")
      .select("id,name,full_name,email,password_hash,status")
      .eq("email", email)
      .maybeSingle();

    if (error) throw error;

    if (
      !customer ||
      !await bcrypt.compare(password, customer.password_hash || "")
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = makeJwt({
      role: "client",
      id: customer.id,
      email: customer.email
    });

    res.json({
      success: true,
      token,
      status: customer.status,
      customer: {
        id: customer.id,
        name: customer.name || customer.full_name,
        email: customer.email,
        status: customer.status
      }
    });
  })
);

// CLIENT PROFILE
app.get(
  "/api/client/me",
  clientAuth,
  asyncRoute(async (req, res) => {

    const { data, error } = await db
      .from("customers")
      .select("id,name,full_name,email,phone,business_name,plan,amount,status,created_at")
      .eq("id", req.client.id)
      .single();

    if (error) throw error;

    res.json({
      success: true,
      customer: data
    });
  })
);

// ADMIN LOGIN
app.post(
  "/api/admin/login",
  authLimiter,
  asyncRoute(async (req, res) => {

    const email = safeString(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (!ADMIN_EMAIL || email !== ADMIN_EMAIL) {
      return res.status(401).json({
        success: false,
        message: "Admin login failed."
      });
    }

    const { data: authData, error: authError } =
      await db.auth.signInWithPassword({
        email,
        password
      });

    if (authError || !authData.user) {
      return res.status(401).json({
        success: false,
        message: "Admin login failed."
      });
    }

    const { data: adminRecord, error } = await db
      .from("admin_users")
      .select("user_id")
      .eq("user_id", authData.user.id)
      .maybeSingle();

    if (error) throw error;

    if (!adminRecord) {
      return res.status(403).json({
        success: false,
        message: "This user is not an admin."
      });
    }

    const token = makeJwt({
      role: "admin",
      email,
      id: authData.user.id
    });

    res.json({
      success: true,
      token,
      email
    });
  })
);

// ADMIN PROFILE
app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    email: req.admin.email
  });
});
// ===============================
// PART 2: PAYMENTS & ADMIN CONTROL
// ===============================

// Get payment configuration
app.get("/api/payment/config", clientAuth, (req, res) => {
  res.json({
    success: true,
    upi_id: process.env.UPI_ID || "",
    upi_name: process.env.UPI_NAME || "",
    plans: [
      { id: "starter", name: "Starter", amount: 4999 },
      { id: "growth", name: "Growth", amount: 7999 },
      { id: "business", name: "Business", amount: 9999 }
    ]
  });
});

// Submit UPI payment proof
app.post(
  "/api/payment/submit",
  clientAuth,
  authLimiter,
  upload.single("screenshot"),
  asyncRoute(async (req, res) => {
    const amount = Number(req.body.amount);
    const utr = safeString(req.body.utr, 50);

    if (![4999, 7999, 9999].includes(amount)) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment amount"
      });
    }

    if (!utr || utr.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Valid UTR number is required"
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Payment screenshot is required"
      });
    }

    const { data: existing, error: existingError } = await supabase
      .from("payments")
      .select("id")
      .eq("customer_id", req.customer.id)
      .eq("status", "pending")
      .limit(1);

    if (existingError) throw existingError;

    if (existing && existing.length) {
      return res.status(409).json({
        success: false,
        message: "Your previous payment is still pending approval"
      });
    }

    const extension = req.file.mimetype === "image/png"
      ? "png"
      : req.file.mimetype === "image/webp"
      ? "webp"
      : req.file.mimetype === "application/pdf"
      ? "pdf"
      : "jpg";

    const filePath = `${req.customer.id}/${crypto.randomUUID()}.${extension}`;

    const { error: uploadError } = await supabase.storage
      .from("payment-proofs")
      .upload(filePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) throw uploadError;

    const { data, error } = await supabase
      .from("payments")
      .insert({
        customer_id: req.customer.id,
        amount,
        payment_method: "UPI",
        utr,
        screenshot_path: filePath,
        status: "pending"
      })
      .select("id,amount,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Payment submitted. Waiting for admin approval.",
      payment: data
    });
  })
);

// Client payment history
app.get(
  "/api/payment/history",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("payments")
      .select("id,amount,payment_method,utr,status,created_at,verified_at,rejection_reason")
      .eq("customer_id", req.customer.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, payments: data || [] });
  })
);

// Admin dashboard statistics
app.get(
  "/api/admin/dashboard",
  adminAuth,
  asyncRoute(async (req, res) => {
    const [clients, payments, pending, keys] = await Promise.all([
      supabase.from("customers").select("id", { count: "exact", head: true }),
      supabase.from("payments").select("id", { count: "exact", head: true }),
      supabase.from("payments").select("id", { count: "exact", head: true }).eq("status", "pending"),
      supabase.from("api_keys").select("id", { count: "exact", head: true }).eq("status", "active")
    ]);

    for (const result of [clients, payments, pending, keys]) {
      if (result.error) throw result.error;
    }

    res.json({
      success: true,
      stats: {
        total_clients: clients.count || 0,
        total_payments: payments.count || 0,
        pending_payments: pending.count || 0,
        active_api_keys: keys.count || 0
      }
    });
  })
);

// Admin: list clients
app.get(
  "/api/admin/clients",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("customers")
      .select("id,full_name,business_name,email,phone,plan,amount,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, clients: data || [] });
  })
);

// Admin: list payments
app.get(
  "/api/admin/payments",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("payments")
      .select(`
        id,customer_id,amount,payment_method,utr,
        screenshot_path,status,created_at,verified_at,rejection_reason,
        customers(full_name,business_name,email,phone)
      `)
      .order("created_at", { ascending: false });

    if (error) throw error;

    const payments = (data || []).map(payment => ({
      ...payment,
      full_name: payment.customers?.full_name || "",
      business_name: payment.customers?.business_name || "",
      email: payment.customers?.email || "",
      phone: payment.customers?.phone || ""
    }));

    res.json({ success: true, payments });
  })
);

// Admin: view private payment screenshot
app.get(
  "/api/admin/payments/:id/proof",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data: payment, error } = await supabase
      .from("payments")
      .select("screenshot_path")
      .eq("id", req.params.id)
      .single();

    if (error || !payment) {
      return res.status(404).json({
        success: false,
        message: "Payment proof not found"
      });
    }

    const { data, error: storageError } = await supabase.storage
      .from("payment-proofs")
      .createSignedUrl(payment.screenshot_path, 300);

    if (storageError) throw storageError;

    res.json({
      success: true,
      url: data.signedUrl
    });
  })
);

// Admin: approve or reject payment
app.post(
  "/api/admin/payments/:id/review",
  adminAuth,
  asyncRoute(async (req, res) => {
    const action = safeString(req.body.action, 20);
    const reason = safeString(req.body.reason, 300);

    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({
        success: false,
        message: "Action must be approve or reject"
      });
    }

    const { data: payment, error: paymentError } = await supabase
      .from("payments")
      .select("id,customer_id,status")
      .eq("id", req.params.id)
      .single();

    if (paymentError || !payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found"
      });
    }

    if (payment.status !== "pending") {
      return res.status(409).json({
        success: false,
        message: "This payment has already been reviewed"
      });
    }

    const paymentUpdate = {
      status: action === "approve" ? "approved" : "rejected",
      verified_at: new Date().toISOString(),
      rejection_reason: action === "reject" ? (reason || "Payment rejected") : null
    };

    const { error: updatePaymentError } = await supabase
      .from("payments")
      .update(paymentUpdate)
      .eq("id", payment.id)
      .eq("status", "pending");

    if (updatePaymentError) throw updatePaymentError;

    const { error: customerError } = await supabase
      .from("customers")
      .update({
        status: action === "approve" ? "approved" : "pending"
      })
      .eq("id", payment.customer_id);

    if (customerError) throw customerError;

    res.json({
      success: true,
      message: action === "approve"
        ? "Payment approved and client activated"
        : "Payment rejected. Client can submit payment again."
    });
  })
);
// ===============================
// PART 3: API KEYS & WHATSAPP API
// ===============================

// Generate ADS GROWTH API key
app.post(
  "/api/client/api-keys",
  clientAuth,
  asyncRoute(async (req, res) => {
    const name = safeString(req.body.name, 60) || "My API Key";

    const { data: customer, error: customerError } = await supabase
      .from("customers")
      .select("status")
      .eq("id", req.customer.id)
      .single();

    if (customerError) throw customerError;

    if (customer.status !== "approved") {
      return res.status(403).json({
        success: false,
        message: "Your account must be approved first"
      });
    }

    const rawKey = "adsg_" + crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
      .from("api_keys")
      .insert({
        customer_id: req.customer.id,
        name,
        key_hash: hashApiKey(rawKey),
        encrypted_key: encryptSecret(rawKey),
        key_prefix: rawKey.slice(0, 13),
        status: "active"
      })
      .select("id,name,key_prefix,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Save your API key now. It will not be shown again.",
      api_key: rawKey,
      details: data
    });
  })
);

// List client API keys
app.get(
  "/api/client/api-keys",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("customer_id", req.customer.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, api_keys: data || [] });
  })
);

// Revoke client API key
app.delete(
  "/api/client/api-keys/:id",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .eq("customer_id", req.customer.id)
      .select("id")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    res.json({ success: true, message: "API key revoked" });
  })
);

// Authenticate ADS GROWTH platform API key
async function platformApiAuth(req, res, next) {
  try {
    const key = safeString(
      req.headers["x-api-key"] ||
      (req.headers.authorization || "").replace(/^Bearer\s+/i, ""),
      200
    );

    if (!key.startsWith("adsg_")) {
      return res.status(401).json({
        success: false,
        message: "Valid ADS GROWTH API key required"
      });
    }

    const { data: apiKey, error } = await supabase
      .from("api_keys")
      .select("id,customer_id,status")
      .eq("key_hash", hashApiKey(key))
      .eq("status", "active")
      .maybeSingle();

    if (error) throw error;

    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: "Invalid or revoked API key"
      });
    }

    const { data: customer, error: customerError } = await supabase
      .from("customers")
      .select("id,status")
      .eq("id", apiKey.customer_id)
      .single();

    if (customerError || !customer || customer.status !== "approved") {
      return res.status(403).json({
        success: false,
        message: "Client account is not active"
      });
    }

    req.platform = {
      apiKeyId: apiKey.id,
      customerId: apiKey.customer_id
    };

    next();
  } catch (error) {
    next(error);
  }
}

// Get connected WhatsApp account
app.get(
  "/api/client/whatsapp",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("whatsapp_connections")
      .select("id,phone_number_id,waba_id,status,updated_at")
      .eq("customer_id", req.customer.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      success: true,
      connection: data || null
    });
  })
);

// Connect WhatsApp Cloud API using Meta credentials
app.post(
  "/api/client/whatsapp/connect",
  clientAuth,
  authLimiter,
  asyncRoute(async (req, res) => {
    const phoneNumberId = safeString(req.body.phone_number_id, 100);
    const wabaId = safeString(req.body.waba_id, 100);
    const accessToken = safeString(req.body.access_token, 5000);

    if (!phoneNumberId || !wabaId || !accessToken) {
      return res.status(400).json({
        success: false,
        message: "Phone Number ID, WhatsApp Business Account ID and access token are required"
      });
    }

    const graphVersion = process.env.META_GRAPH_VERSION || GRAPH_VERSION;

    const verifyResponse = await fetch(
      `https://graph.facebook.com/${graphVersion}/${phoneNumberId}?fields=id,display_phone_number,verified_name`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const verifyData = await verifyResponse.json();

    if (!verifyResponse.ok || verifyData.error) {
      return res.status(400).json({
        success: false,
        message: "Meta could not verify this WhatsApp phone number. Check your credentials."
      });
    }

    const { error } = await supabase
      .from("whatsapp_connections")
      .upsert({
        customer_id: req.customer.id,
        phone_number_id: phoneNumberId,
        waba_id: wabaId,
        access_token_encrypted: encryptSecret(accessToken),
        status: "connected",
        updated_at: new Date().toISOString()
      }, {
        onConflict: "customer_id"
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "WhatsApp Cloud API connected successfully",
      phone: verifyData.display_phone_number || "",
      verified_name: verifyData.verified_name || ""
    });
  })
);

// Disconnect WhatsApp account
app.delete(
  "/api/client/whatsapp",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { error } = await supabase
      .from("whatsapp_connections")
      .delete()
      .eq("customer_id", req.customer.id);

    if (error) throw error;

    res.json({
      success: true,
      message: "WhatsApp account disconnected"
    });
  })
);

// Send WhatsApp message through platform API
app.post(
  "/api/v1/messages/send",
  platformApiAuth,
  asyncRoute(async (req, res) => {
    const to = safeString(req.body.to, 30);
    const message = safeString(req.body.message, 4096);

    if (!to || !/^\d{8,15}$/.test(to)) {
      return res.status(400).json({
        success: false,
        message: "Enter recipient number with country code, digits only"
      });
    }

    if (!message) {
      return res.status(400).json({
        success: false,
        message: "Message text is required"
      });
    }

    const { data: connection, error } = await supabase
      .from("whatsapp_connections")
      .select("phone_number_id,access_token_encrypted,status")
      .eq("customer_id", req.platform.customerId)
      .maybeSingle();

    if (error) throw error;

    if (!connection || connection.status !== "connected") {
      return res.status(400).json({
        success: false,
        message: "Connect your WhatsApp Cloud API account first"
      });
    }

    const accessToken = decryptSecret(connection.access_token_encrypted);
    const graphVersion = process.env.META_GRAPH_VERSION || GRAPH_VERSION;

    const graphResponse = await fetch(
      `https://graph.facebook.com/${graphVersion}/${connection.phone_number_id}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          recipient_type: "individual",
          to,
          type: "text",
          text: {
            preview_url: false,
            body: message
          }
        })
      }
    );

    const graphData = await graphResponse.json();

    if (!graphResponse.ok || graphData.error) {
      return res.status(502).json({
        success: false,
        message: "Meta WhatsApp message sending failed",
        error: graphData.error?.message || "Unknown Meta API error"
      });
    }

    const messageId = graphData.messages?.[0]?.id || null;

    await supabase.from("whatsapp_messages").insert({
      customer_id: req.platform.customerId,
      direction: "outgoing",
      recipient: to,
      message_type: "text",
      message_body: message,
      meta_message_id: messageId,
      status: "sent"
    });

    await supabase.from("api_usage").insert({
      customer_id: req.platform.customerId,
      api_key_id: req.platform.apiKeyId,
      endpoint: "/api/v1/messages/send",
      method: "POST",
      status_code: 200
    });

    res.json({
      success: true,
      message: "WhatsApp message accepted by Meta",
      message_id: messageId
    });
  })
);

// API key test endpoint
app.get(
  "/api/v1/account",
  platformApiAuth,
  asyncRoute(async (req, res) => {
    res.json({
      success: true,
      customer_id: req.platform.customerId,
      message: "ADS GROWTH API key is working"
    });
  })
);
             
// ===============================
// PART 4: WEBHOOK, ADMIN API & SERVER
// ===============================

// Meta webhook verification
app.get("/webhook/meta", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    token &&
    process.env.META_WEBHOOK_VERIFY_TOKEN &&
    constantTimeEqual(
      String(token),
      String(process.env.META_WEBHOOK_VERIFY_TOKEN)
    )
  ) {
    return res.status(200).send(String(challenge || ""));
  }

  return res.sendStatus(403);
});

// Verify that webhook request really came from Meta
function verifyMetaSignature(req) {
  const appSecret = process.env.META_APP_SECRET;

  if (!appSecret || !Buffer.isBuffer(req.body)) {
    return false;
  }

  const signature = req.headers["x-hub-signature-256"];

  if (!signature || !signature.startsWith("sha256=")) {
    return false;
  }

  const expected = "sha256=" + crypto
    .createHmac("sha256", appSecret)
    .update(req.body)
    .digest("hex");

  return constantTimeEqual(signature, expected);
}

// Receive incoming WhatsApp messages and status updates
app.post("/webhook/meta", async (req, res) => {
  try {
    if (!verifyMetaSignature(req)) {
      return res.sendStatus(401);
    }

    const payload = JSON.parse(req.body.toString("utf8"));

    if (payload.object !== "whatsapp_business_account") {
      return res.sendStatus(200);
    }

    for (const entry of payload.entry || []) {
      for (const change of entry.changes || []) {
        if (change.field !== "messages") continue;

        const value = change.value || {};
        const phoneNumberId = value.metadata?.phone_number_id;

        if (!phoneNumberId) continue;

        const { data: connection, error: connectionError } = await supabase
          .from("whatsapp_connections")
          .select("customer_id")
          .eq("phone_number_id", phoneNumberId)
          .maybeSingle();

        if (connectionError) throw connectionError;
        if (!connection) continue;

        // Incoming messages
        for (const message of value.messages || []) {
          const messageBody =
            message.text?.body ||
            message.button?.text ||
            message.interactive?.button_reply?.title ||
            message.interactive?.list_reply?.title ||
            "";

          const { error: messageError } = await supabase
            .from("whatsapp_messages")
            .insert({
              customer_id: connection.customer_id,
              direction: "incoming",
              recipient: message.from || "",
              message_type: message.type || "unknown",
              message_body: messageBody,
              meta_message_id: message.id || null,
              status: "received"
            });

          if (messageError) throw messageError;
        }

        // Delivery, read and failure status updates
        for (const status of value.statuses || []) {
          if (!status.id) continue;

          const { error: statusError } = await supabase
            .from("whatsapp_messages")
            .update({
              status: status.status || "unknown"
            })
            .eq("meta_message_id", status.id)
            .eq("customer_id", connection.customer_id);

          if (statusError) throw statusError;
        }
      }
    }

    return res.sendStatus(200);
  } catch (error) {
    console.error("Meta webhook processing error:", error.message);
    return res.sendStatus(200);
  }
});

// Admin: list all API keys
app.get(
  "/api/admin/api-keys",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("api_keys")
      .select("id,customer_id,name,key_prefix,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      api_keys: data || []
    });
  })
);

// Admin: revoke an API key
app.post(
  "/api/admin/api-keys/:id/revoke",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .select("id")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        success: false,
        message: "API key not found"
      });
    }

    res.json({
      success: true,
      message: "API key revoked"
    });
  })
);

// Client: API usage report
app.get(
  "/api/client/usage",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await supabase
      .from("api_usage")
      .select("endpoint,method,status_code,created_at")
      .eq("customer_id", req.customer.id)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) throw error;

    res.json({
      success: true,
      usage: data || [],
      total_records: (data || []).length
    });
  })
);

// Public API information
app.get("/api", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH AGENCY API",
    version: "1.0.0",
    endpoints: {
      account: "GET /api/v1/account",
      send_message: "POST /api/v1/messages/send",
      webhook: "/webhook/meta"
    }
  });
});

// Central error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  const status = err.status || err.statusCode || 500;

  res.status(status).json({
    success: false,
    message: status >= 500
      ? "Internal server error"
      : err.message || "Request failed"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`ADS GROWTH API running on port ${PORT}`);
});
             
