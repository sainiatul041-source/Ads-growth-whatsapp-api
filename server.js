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
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SUPABASE_ANON_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG or WEBP images are allowed."));
    }
    cb(null, true);
  }
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", limiter);

function sendError(res, message, status = 400) {
  return res.status(status).json({ success: false, message });
}

function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function verifyToken(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) return sendError(res, "Login required.", 401);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return sendError(res, "Session expired. Please login again.", 401);
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin" ||
      String(req.user.email || "").toLowerCase() !== ADMIN_EMAIL) {
    return sendError(res, "Admin access denied.", 403);
  }
  next();
}

function clientOnly(req, res, next) {
  if (req.user.role !== "client" || !req.user.customer_id) {
    return sendError(res, "Client access denied.", 403);
  }
  next();
}

const encryptionKey = crypto
  .createHash("sha256")
  .update("ADS_GROWTH_API_KEY_ENCRYPTION:" + JWT_SECRET)
  .digest();

function encryptKey(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
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

function decryptKey(value) {
  const parts = String(value || "").split(":");
  if (parts.length !== 3) throw new Error("Invalid encrypted key.");

  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const encrypted = Buffer.from(parts[2], "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

function hashKey(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

async function createCustomerKey(customerId) {
  const rawKey = "AG_" + crypto.randomBytes(32).toString("hex");

  const { data, error } = await db
    .from("api_keys")
    .insert({
      customer_id: customerId,
      key_hash: hashKey(rawKey),
      key_prefix: rawKey.slice(0, 11),
      key_encrypted: encryptKey(rawKey),
      status: "active"
    })
    .select()
    .single();

  if (error) throw error;

  return { record: data, api_key: rawKey };
}

async function getCustomerByLogin(login) {
  const value = String(login || "").trim();
  if (!value) return null;

  let query = db.from("customers").select("*").limit(1);

  if (value.includes("@")) {
    query = query.ilike("email", value);
  } else {
    query = query.eq("phone", value);
  }

  const { data, error } = await query.maybeSingle();
  if (error) throw error;
  return data;
}

app.get("/", (req, res) => {
  res.json({ success: true, service: "ADS GROWTH", status: "running" });
});

app.get("/health", (req, res) => {
  res.json({ success: true, status: "ok" });
});
// CLIENT REGISTRATION
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, business_name } = req.body;

    if (!name || (!email && !phone)) {
      return sendError(res, "Name and email or phone are required.");
    }

    const customer = {
      name: String(name).trim(),
      email: email ? String(email).trim().toLowerCase() : null,
      phone: phone ? String(phone).trim() : null,
      business_name: business_name ? String(business_name).trim() : null,
      status: "pending"
    };

    const { data, error } = await db
      .from("customers")
      .insert(customer)
      .select("id,name,email,phone,status")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "Registration submitted. Wait for admin approval.",
      customer: data
    });
  } catch (error) {
    console.error("Registration:", error);
    sendError(res, error.message || "Registration failed.", 500);
  }
});

// PAYMENT SCREENSHOT UPLOAD
app.post(
  ["/api/payment/upload", "/api/payments/upload"],
  upload.single("screenshot"),
  async (req, res) => {
    try {
      const { customer_id, utr } = req.body;

      if (!customer_id || !utr || !req.file) {
        return sendError(res, "Customer ID, UTR and screenshot are required.");
      }

      const { data: customer, error: customerError } = await db
        .from("customers")
        .select("id")
        .eq("id", customer_id)
        .maybeSingle();

      if (customerError) throw customerError;
      if (!customer) return sendError(res, "Customer not found.", 404);

      const extension = req.file.mimetype === "image/png" ? "png" :
        req.file.mimetype === "image/webp" ? "webp" : "jpg";

      const fileName = `${customer_id}/${Date.now()}-${crypto.randomBytes(4).toString("hex")}.${extension}`;

      const { error: storageError } = await db.storage
        .from("payment-proofs")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (storageError) throw storageError;

      const { data: urlData } = db.storage
        .from("payment-proofs")
        .getPublicUrl(fileName);

      const { data, error } = await db
        .from("payments")
        .insert({
          customer_id,
          utr: String(utr).trim(),
          screenshot_url: urlData.publicUrl,
          status: "pending"
        })
        .select()
        .single();

      if (error) throw error;

      res.json({
        success: true,
        message: "Payment submitted successfully.",
        payment: data
      });
    } catch (error) {
      console.error("Payment upload:", error);
      sendError(res, error.message || "Payment upload failed.", 500);
    }
  }
);

// ADMIN LOGIN
app.post("/api/admin/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (email !== ADMIN_EMAIL) {
      return sendError(res, "Admin access denied.", 403);
    }

    if (!password) return sendError(res, "Password is required.");

    const { data, error } = await authClient.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.user) {
      return sendError(res, "Invalid admin email or password.", 401);
    }

    const { data: admin, error: adminError } = await db
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) throw adminError;
    if (!admin) return sendError(res, "This account is not an approved admin.", 403);

    const token = makeToken({
      role: "admin",
      email,
      user_id: data.user.id
    });

    res.json({
      success: true,
      token,
      admin: { email }
    });
  } catch (error) {
    console.error("Admin login:", error);
    sendError(res, error.message || "Admin login failed.", 500);
  }
});

// ADMIN PROFILE CHECK
app.get("/api/admin/me", verifyToken, adminOnly, (req, res) => {
  res.json({ success: true, admin: { email: req.user.email } });
});

// ADMIN CUSTOMER LIST
app.get("/api/admin/customers", verifyToken, adminOnly, async (req, res) => {
  try {
    const { data, error } = await db
      .from("customers")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, customers: data || [] });
  } catch (error) {
    sendError(res, error.message || "Could not load customers.", 500);
  }
});

// ADMIN PAYMENT LIST
app.get("/api/admin/payments", verifyToken, adminOnly, async (req, res) => {
  try {
    const { data, error } = await db
      .from("payments")
      .select("*,customers(name,email,phone)")
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, payments: data || [] });
  } catch (error) {
    sendError(res, error.message || "Could not load payments.", 500);
  }
});

// APPROVE PAYMENT AND CUSTOMER
app.post("/api/admin/payments/:id/approve", verifyToken, adminOnly, async (req, res) => {
  try {
    const { data: payment, error: paymentError } = await db
      .from("payments")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (paymentError || !payment) {
      return sendError(res, "Payment not found.", 404);
    }

    const { data: customer, error: customerError } = await db
      .from("customers")
      .select("*")
      .eq("id", payment.customer_id)
      .single();

    if (customerError || !customer) {
      return sendError(res, "Customer not found.", 404);
    }

    const { error: updatePaymentError } = await db
      .from("payments")
      .update({ status: "approved" })
      .eq("id", payment.id);

    if (updatePaymentError) throw updatePaymentError;

    const { error: updateCustomerError } = await db
      .from("customers")
      .update({ status: "approved" })
      .eq("id", customer.id);

    if (updateCustomerError) throw updateCustomerError;

    let temporaryPassword = null;

    if (!customer.password_hash) {
      temporaryPassword = crypto.randomBytes(5).toString("hex");
      const passwordHash = await bcrypt.hash(temporaryPassword, 12);

      const { error } = await db
        .from("customers")
        .update({ password_hash: passwordHash })
        .eq("id", customer.id);

      if (error) throw error;
    }

    const { data: existingKeys, error: keyError } = await db
      .from("api_keys")
      .select("id")
      .eq("customer_id", customer.id)
      .eq("status", "active")
      .limit(1);

    if (keyError) throw keyError;

    let newKey = null;
    if (!existingKeys || existingKeys.length === 0) {
      const created = await createCustomerKey(customer.id);
      newKey = created.api_key;
    }

    res.json({
      success: true,
      message: "Customer approved successfully.",
      temporary_password: temporaryPassword,
      api_key: newKey
    });
  } catch (error) {
    console.error("Approve payment:", error);
    sendError(res, error.message || "Approval failed.", 500);
  }
});

// REJECT PAYMENT
app.post("/api/admin/payments/:id/reject", verifyToken, adminOnly, async (req, res) => {
  try {
    const { error } = await db
      .from("payments")
      .update({ status: "rejected" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "Payment rejected." });
  } catch (error) {
    sendError(res, error.message || "Could not reject payment.", 500);
  }
});
// ADMIN: GENERATE CUSTOMER API KEY
app.post("/api/admin/customers/:id/api-key", verifyToken, adminOnly, async (req, res) => {
  try {
    const { data: customer, error } = await db
      .from("customers")
      .select("id,status")
      .eq("id", req.params.id)
      .single();

    if (error || !customer) return sendError(res, "Customer not found.", 404);
    if (customer.status !== "approved") {
      return sendError(res, "Customer is not approved.", 400);
    }

    const created = await createCustomerKey(customer.id);

    res.json({
      success: true,
      message: "API key generated.",
      api_key: created.api_key,
      key: created.record
    });
  } catch (error) {
    sendError(res, error.message || "Key generation failed.", 500);
  }
});

// ADMIN: API KEY LIST
app.get("/api/admin/api-keys", verifyToken, adminOnly, async (req, res) => {
  try {
    const { data, error } = await db
      .from("api_keys")
      .select("id,customer_id,key_prefix,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json({ success: true, api_keys: data || [], keys: data || [] });
  } catch (error) {
    sendError(res, error.message || "Could not load API keys.", 500);
  }
});

// ADMIN: REVOKE API KEY
app.post("/api/admin/api-keys/:id/revoke", verifyToken, adminOnly, async (req, res) => {
  try {
    const { error } = await db
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id);

    if (error) throw error;
    res.json({ success: true, message: "API key revoked." });
  } catch (error) {
    sendError(res, error.message || "Could not revoke key.", 500);
  }
});

// CLIENT LOGIN: EMAIL OR PHONE + PASSWORD
app.post("/api/client/login", async (req, res) => {
  try {
    const login = req.body.email || req.body.phone || req.body.login;
    const password = String(req.body.password || "");

    if (!login || !password) {
      return sendError(res, "Email/phone and password required.");
    }

    const customer = await getCustomerByLogin(login);

    if (!customer || !customer.password_hash) {
      return sendError(res, "Invalid login details.", 401);
    }

    const validPassword = await bcrypt.compare(password, customer.password_hash);

    if (!validPassword) {
      return sendError(res, "Invalid login details.", 401);
    }

    if (customer.status !== "approved") {
      return sendError(res, "Your account is not approved yet.", 403);
    }

    const token = makeToken({
      role: "client",
      customer_id: customer.id
    });

    res.json({
      success: true,
      token,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
        status: customer.status
      }
    });
  } catch (error) {
    console.error("Client login:", error);
    sendError(res, error.message || "Client login failed.", 500);
  }
});

// CLIENT PROFILE / DASHBOARD
app.get("/api/client/me", verifyToken, clientOnly, async (req, res) => {
  try {
    const { data: customer, error } = await db
      .from("customers")
      .select("id,name,email,phone,business_name,status,created_at")
      .eq("id", req.user.customer_id)
      .single();

    if (error) throw error;

    const { data: keys, error: keyError } = await db
      .from("api_keys")
      .select("id,key_prefix,status,created_at")
      .eq("customer_id", req.user.customer_id)
      .order("created_at", { ascending: false });

    if (keyError) throw keyError;

    res.json({
      success: true,
      customer,
      api_keys: keys || [],
      keys: keys || []
    });
  } catch (error) {
    sendError(res, error.message || "Could not load dashboard.", 500);
  }
});

// CLIENT: GENERATE NEW API KEY
app.post("/api/client/api-key", verifyToken, clientOnly, async (req, res) => {
  try {
    const { data: customer, error } = await db
      .from("customers")
      .select("id,status")
      .eq("id", req.user.customer_id)
      .single();

    if (error || !customer) return sendError(res, "Customer not found.", 404);
    if (customer.status !== "approved") {
      return sendError(res, "Account is not approved.", 403);
    }

    const created = await createCustomerKey(customer.id);

    res.json({
      success: true,
      message: "API key generated.",
      api_key: created.api_key,
      key: created.record
    });
  } catch (error) {
    sendError(res, error.message || "Key generation failed.", 500);
  }
});

// CLIENT: VIEW / REVEAL EXISTING API KEY
app.get("/api/client/api-keys/:id/reveal", verifyToken, clientOnly, async (req, res) => {
  try {
    const { data: key, error } = await db
      .from("api_keys")
      .select("id,customer_id,key_encrypted,status")
      .eq("id", req.params.id)
      .eq("customer_id", req.user.customer_id)
      .single();

    if (error || !key) return sendError(res, "API key not found.", 404);
    if (key.status !== "active") {
      return sendError(res, "This API key is not active.", 403);
    }
    if (!key.key_encrypted) {
      return sendError(res, "This old key cannot be displayed. Generate a new key.", 400);
    }

    const apiKey = decryptKey(key.key_encrypted);
    res.json({ success: true, api_key: apiKey, key: apiKey });
  } catch (error) {
    console.error("Reveal key:", error);
    sendError(res, "Could not reveal API key.", 500);
  }
});

// CLIENT: REVOKE OWN KEY
app.post("/api/client/api-keys/:id/revoke", verifyToken, clientOnly, async (req, res) => {
  try {
    const { data, error } = await db
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .eq("customer_id", req.user.customer_id)
      .select("id")
      .maybeSingle();

    if (error) throw error;
    if (!data) return sendError(res, "API key not found.", 404);

    res.json({ success: true, message: "API key revoked." });
  } catch (error) {
    sendError(res, error.message || "Could not revoke key.", 500);
  }
});

// API KEY VALIDATION
app.post("/api/keys/validate", async (req, res) => {
  try {
    const apiKey = String(req.body.api_key || req.body.key || "").trim();
    if (!apiKey) return sendError(res, "API key is required.");

    const { data, error } = await db
      .from("api_keys")
      .select("id,customer_id,status")
      .eq("key_hash", hashKey(apiKey))
      .maybeSingle();

    if (error) throw error;

    if (!data || data.status !== "active") {
      return res.status(401).json({
        success: false,
        valid: false,
        message: "Invalid or revoked API key."
      });
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

// NOT FOUND
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found."
  });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({
    success: false,
    message: err.message || "Internal server error."
  });
});

app.listen(PORT, () => {
  console.log(`ADS GROWTH server running on port ${PORT}`);
});
