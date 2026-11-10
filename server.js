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
  crossOriginResourcePolicy: {
    policy: "cross-origin"
  }
}));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({
  extended: true,
  limit: "2mb"
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPG, PNG and WEBP images allowed."));
    }
  }
});

function sendError(res, message, status = 400) {
  return res.status(status).json({
    success: false,
    message
  });
}

function hashKey(key) {
  return crypto
    .createHash("sha256")
    .update(key)
    .digest("hex");
}

function encryptionKey() {
  return crypto
    .createHash("sha256")
    .update(process.env.JWT_SECRET)
    .digest();
}

function encryptKey(value) {
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

  const tag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    tag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptKey(value) {
  const parts = value.split(":");

  if (parts.length !== 3) {
    throw new Error("Invalid encrypted key.");
  }

  const [ivHex, tagHex, encryptedHex] = parts;

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
  return jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function verifyJwt(token) {
  return jwt.verify(
    token,
    process.env.JWT_SECRET
  );
}

function adminAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return sendError(res, "Admin login required.", 401);
    }

    const decoded = verifyJwt(token);

    if (
      decoded.role !== "admin" ||
      decoded.email !== ADMIN_EMAIL
    ) {
      return sendError(res, "Unauthorized admin.", 403);
    }

    req.admin = decoded;
    next();

  } catch (error) {
    return sendError(res, "Invalid or expired token.", 401);
  }
}

function clientAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return sendError(res, "Client login required.", 401);
    }

    const decoded = verifyJwt(token);

    if (decoded.role !== "client" || !decoded.id) {
      return sendError(res, "Unauthorized client.", 403);
    }

    req.client = decoded;
    next();

  } catch (error) {
    return sendError(res, "Invalid or expired token.", 401);
  }
}

// DUPLICATE EMAIL / PHONE SAFE LOGIN SEARCH
async function getCustomerByLogin(login, password) {
  const value = String(login || "").trim();

  if (!value) return null;

  let query = db
    .from("customers")
    .select("*");

  if (value.includes("@")) {
    query = query.ilike("email", value);
  } else {
    query = query.eq("phone", value);
  }

  const { data, error } = await query
    .order("created_at", { ascending: false })
    .limit(20);

  if (error) throw error;

  if (!data || data.length === 0) {
    return null;
  }

  for (const customer of data) {
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

function createCustomerKey() {
  return "ADS_" + crypto.randomBytes(32).toString("hex");
  }
// HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH",
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
app.post("/api/register", loginLimiter, async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      business_name,
      password
    } = req.body;

    if (!name || !email || !phone || !password) {
      return sendError(res, "All required fields are mandatory.");
    }

    if (String(password).length < 6) {
      return sendError(res, "Password must be at least 6 characters.");
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();

    const { data: emailRows, error: emailError } = await db
      .from("customers")
      .select("id")
      .ilike("email", cleanEmail)
      .limit(1);

    if (emailError) throw emailError;

    const { data: phoneRows, error: phoneError } = await db
      .from("customers")
      .select("id")
      .eq("phone", cleanPhone)
      .limit(1);

    if (phoneError) throw phoneError;

    if (
      (emailRows && emailRows.length) ||
      (phoneRows && phoneRows.length)
    ) {
      return sendError(
        res,
        "Email or phone already registered.",
        409
      );
    }

    const passwordHash = await bcrypt.hash(
      String(password),
      12
    );

    const { data, error } = await db
      .from("customers")
      .insert({
        name: String(name).trim(),
        email: cleanEmail,
        phone: cleanPhone,
        business_name: business_name
          ? String(business_name).trim()
          : null,
        password_hash: passwordHash,
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
    console.error("Registration error:", error);
    sendError(
      res,
      error.message || "Registration failed.",
      500
    );
  }
});

// PAYMENT SCREENSHOT UPLOAD
async function uploadPaymentProof(req, res) {
  try {
    const customerId = String(
      req.body.customer_id || ""
    ).trim();

    const utr = String(
      req.body.utr || ""
    ).trim();

    const file = req.file;

    if (!customerId || !utr || !file) {
      return sendError(
        res,
        "Customer ID, UTR and screenshot required."
      );
    }

    const { data: customer, error: customerError } = await db
      .from("customers")
      .select("id")
      .eq("id", customerId)
      .maybeSingle();

    if (customerError) throw customerError;

    if (!customer) {
      return sendError(res, "Customer not found.", 404);
    }

    const fileName =
      `${customerId}/${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;

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

    const { data, error } = await db
      .from("payments")
      .insert({
        customer_id: customerId,
        utr,
        screenshot_url: publicData.publicUrl,
        status: "pending"
      })
      .select("*")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Payment proof submitted.",
      payment: data
    });

  } catch (error) {
    console.error("Payment upload error:", error);
    sendError(
      res,
      error.message || "Payment upload failed.",
      500
    );
  }
}

app.post(
  "/api/payment/upload",
  upload.single("screenshot"),
  uploadPaymentProof
);

app.post(
  "/api/payments/upload",
  upload.single("screenshot"),
  uploadPaymentProof
);

// ADMIN LOGIN
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return sendError(res, "Email and password required.");
    }

    if (email !== ADMIN_EMAIL) {
      return sendError(
        res,
        "Invalid admin login details.",
        401
      );
    }

    const { data, error } =
      await authClient.auth.signInWithPassword({
        email,
        password
      });

    if (error || !data.user) {
      return sendError(
        res,
        "Invalid admin login details.",
        401
      );
    }

    const { data: adminRecord, error: adminError } = await db
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) throw adminError;

    if (!adminRecord) {
      return sendError(
        res,
        "Admin access not configured.",
        403
      );
    }

    const token = createToken({
      role: "admin",
      email: ADMIN_EMAIL,
      user_id: data.user.id
    });

    res.json({
      success: true,
      token,
      admin: {
        email: ADMIN_EMAIL
      }
    });

  } catch (error) {
    console.error("Admin login error:", error);
    sendError(
      res,
      error.message || "Admin login failed.",
      500
    );
  }
});

// ADMIN PROFILE
app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    admin: {
      email: ADMIN_EMAIL
    }
  });
});

// ADMIN CUSTOMER LIST
app.get("/api/admin/customers", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db
      .from("customers")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      customers: data || []
    });

  } catch (error) {
    console.error("Customer list error:", error);
    sendError(
      res,
      error.message || "Could not load customers.",
      500
    );
  }
});

// ADMIN PAYMENT LIST
app.get("/api/admin/payments", adminAuth, async (req, res) => {
  try {
    const { data, error } = await db
      .from("payments")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      payments: data || []
    });

  } catch (error) {
    console.error("Payment list error:", error);
    sendError(
      res,
      error.message || "Could not load payments.",
      500
    );
  }
});

// APPROVE PAYMENT AND CUSTOMER
app.post(
  "/api/admin/payments/:id/approve",
  adminAuth,
  async (req, res) => {
    try {
      const { data: payment, error: paymentError } = await db
        .from("payments")
        .update({ status: "approved" })
        .eq("id", req.params.id)
        .select("id,customer_id,status")
        .single();

      if (paymentError) throw paymentError;

      const { error: customerError } = await db
        .from("customers")
        .update({ status: "approved" })
        .eq("id", payment.customer_id);

      if (customerError) throw customerError;

      res.json({
        success: true,
        message: "Payment approved and customer activated."
      });

    } catch (error) {
      console.error("Payment approval error:", error);
      sendError(
        res,
        error.message || "Payment approval failed.",
        500
      );
    }
  }
);

// REJECT PAYMENT
app.post(
  "/api/admin/payments/:id/reject",
  adminAuth,
  async (req, res) => {
    try {
      const { error } = await db
        .from("payments")
        .update({ status: "rejected" })
        .eq("id", req.params.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "Payment rejected."
      });

    } catch (error) {
      console.error("Payment rejection error:", error);
      sendError(
        res,
        error.message || "Payment rejection failed.",
        500
      );
    }
  }
);

// APPROVE CUSTOMER
app.post(
  "/api/admin/customers/:id/approve",
  adminAuth,
  async (req, res) => {
    try {
      const { error } = await db
        .from("customers")
        .update({ status: "approved" })
        .eq("id", req.params.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "Customer approved."
      });

    } catch (error) {
      console.error("Customer approval error:", error);
      sendError(
        res,
        error.message || "Customer approval failed.",
        500
      );
    }
  }
);

// REJECT CUSTOMER
app.post(
  "/api/admin/customers/:id/reject",
  adminAuth,
  async (req, res) => {
    try {
      const { error } = await db
        .from("customers")
        .update({ status: "rejected" })
        .eq("id", req.params.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "Customer rejected."
      });

    } catch (error) {
      console.error("Customer rejection error:", error);
      sendError(
        res,
        error.message || "Customer rejection failed.",
        500
      );
    }
  }
);
// ADMIN RESET CUSTOMER PASSWORD
app.post(
  "/api/admin/customers/:id/reset-password",
  adminAuth,
  async (req, res) => {
    try {
      const temporaryPassword = crypto
        .randomBytes(6)
        .toString("hex");

      const passwordHash = await bcrypt.hash(
        temporaryPassword,
        12
      );

      const { data, error } = await db
        .from("customers")
        .update({
          password_hash: passwordHash
        })
        .eq("id", req.params.id)
        .select("id,name,email,phone")
        .single();

      if (error) throw error;

      res.json({
        success: true,
        message: "Customer password reset successfully.",
        temporary_password: temporaryPassword,
        customer: data
      });

    } catch (error) {
      console.error("Password reset error:", error);
      sendError(
        res,
        error.message || "Password reset failed.",
        500
      );
    }
  }
);

// ADMIN GENERATE API KEY
app.post(
  "/api/admin/customers/:id/api-key",
  adminAuth,
  async (req, res) => {
    try {
      const { data: customer, error: customerError } = await db
        .from("customers")
        .select("id")
        .eq("id", req.params.id)
        .maybeSingle();

      if (customerError) throw customerError;

      if (!customer) {
        return sendError(res, "Customer not found.", 404);
      }

      const apiKey = createCustomerKey();

      const { data, error } = await db
        .from("api_keys")
        .insert({
          customer_id: req.params.id,
          key_hash: hashKey(apiKey),
          key_prefix: apiKey.slice(0, 12),
          key_encrypted: encryptKey(apiKey),
          status: "active"
        })
        .select("id,customer_id,key_prefix,status,created_at")
        .single();

      if (error) throw error;

      res.status(201).json({
        success: true,
        api_key: apiKey,
        key: data
      });

    } catch (error) {
      console.error("Admin key generation:", error);
      sendError(
        res,
        error.message || "API key generation failed.",
        500
      );
    }
  }
);

// ADMIN LIST CUSTOMER API KEYS
app.get(
  "/api/admin/customers/:id/api-keys",
  adminAuth,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("api_keys")
        .select("id,customer_id,key_prefix,status,created_at")
        .eq("customer_id", req.params.id)
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json({
        success: true,
        keys: data || []
      });

    } catch (error) {
      console.error("Admin key list:", error);
      sendError(
        res,
        error.message || "Could not load API keys.",
        500
      );
    }
  }
);

// ADMIN REVEAL API KEY
app.get(
  "/api/admin/api-keys/:id/reveal",
  adminAuth,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("api_keys")
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

      res.json({
        success: true,
        api_key: decryptKey(data.key_encrypted)
      });

    } catch (error) {
      console.error("Admin key reveal:", error);
      sendError(
        res,
        error.message || "Could not reveal API key.",
        500
      );
    }
  }
);

// ADMIN REVOKE API KEY
app.post(
  "/api/admin/api-keys/:id/revoke",
  adminAuth,
  async (req, res) => {
    try {
      const { error } = await db
        .from("api_keys")
        .update({ status: "revoked" })
        .eq("id", req.params.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "API key revoked."
      });

    } catch (error) {
      console.error("Admin key revoke:", error);
      sendError(
        res,
        error.message || "Could not revoke API key.",
        500
      );
    }
  }
);

// CLIENT LOGIN
app.post(
  "/api/client/login",
  loginLimiter,
  async (req, res) => {
    try {
      const login = String(
        req.body.login ||
        req.body.email ||
        req.body.phone ||
        ""
      ).trim();

      const password = String(
        req.body.password || ""
      );

      if (!login || !password) {
        return sendError(
          res,
          "Email/phone and password required."
        );
      }

      const customer = await getCustomerByLogin(
        login,
        password
      );

      if (!customer) {
        return sendError(
          res,
          "Invalid login details.",
          401
        );
      }

      if (customer.status !== "approved") {
        return sendError(
          res,
          "Your account is not approved yet.",
          403
        );
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
      console.error("Client login error:", error);
      sendError(
        res,
        error.message || "Client login failed.",
        500
      );
    }
  }
);

// CLIENT PROFILE
app.get(
  "/api/client/me",
  clientAuth,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("customers")
        .select("id,name,email,phone,business_name,status,created_at")
        .eq("id", req.client.id)
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return sendError(res, "Customer not found.", 404);
      }

      res.json({
        success: true,
        customer: data
      });

    } catch (error) {
      console.error("Client profile:", error);
      sendError(
        res,
        error.message || "Could not load profile.",
        500
      );
    }
  }
);

// CLIENT GENERATE API KEY
app.post(
  "/api/client/api-key",
  clientAuth,
  async (req, res) => {
    try {
      const apiKey = createCustomerKey();

      const { data, error } = await db
        .from("api_keys")
        .insert({
          customer_id: req.client.id,
          key_hash: hashKey(apiKey),
          key_prefix: apiKey.slice(0, 12),
          key_encrypted: encryptKey(apiKey),
          status: "active"
        })
        .select("id,customer_id,key_prefix,status,created_at")
        .single();

      if (error) throw error;

      res.status(201).json({
        success: true,
        api_key: apiKey,
        key: data
      });

    } catch (error) {
      console.error("Client key generation:", error);
      sendError(
        res,
        error.message || "API key generation failed.",
        500
      );
    }
  }
);

// CLIENT LIST API KEYS
app.get(
  "/api/client/api-keys",
  clientAuth,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("api_keys")
        .select("id,key_prefix,status,created_at")
        .eq("customer_id", req.client.id)
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json({
        success: true,
        keys: data || []
      });

    } catch (error) {
      console.error("Client key list:", error);
      sendError(
        res,
        error.message || "Could not load API keys.",
        500
      );
    }
  }
);

// CLIENT REVEAL API KEY
app.get(
  "/api/client/api-keys/:id/reveal",
  clientAuth,
  async (req, res) => {
    try {
      const { data, error } = await db
        .from("api_keys")
        .select("id,key_encrypted,status")
        .eq("id", req.params.id)
        .eq("customer_id", req.client.id)
        .maybeSingle();

      if (error) throw error;

      if (!data || !data.key_encrypted) {
        return sendError(res, "API key not found.", 404);
      }

      if (data.status !== "active") {
        return sendError(res, "API key is revoked.", 400);
      }

      res.json({
        success: true,
        api_key: decryptKey(data.key_encrypted)
      });

    } catch (error) {
      console.error("Client key reveal:", error);
      sendError(
        res,
        error.message || "Could not reveal API key.",
        500
      );
    }
  }
);

// CLIENT REVOKE API KEY
app.post(
  "/api/client/api-keys/:id/revoke",
  clientAuth,
  async (req, res) => {
    try {
      const { error } = await db
        .from("api_keys")
        .update({ status: "revoked" })
        .eq("id", req.params.id)
        .eq("customer_id", req.client.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "API key revoked."
      });

    } catch (error) {
      console.error("Client key revoke:", error);
      sendError(
        res,
        error.message || "Could not revoke API key.",
        500
      );
    }
  }
);

// API KEY VALIDATION
app.post(
  "/api/keys/validate",
  async (req, res) => {
    try {
      const apiKey = String(
        req.body.api_key ||
        req.body.key ||
        ""
      ).trim();

      if (!apiKey) {
        return sendError(res, "API key is required.");
      }

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
      console.error("Key validation:", error);
      sendError(
        res,
        error.message || "Key validation failed.",
        500
      );
    }
  }
);

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

// START SERVER
app.listen(PORT, () => {
  console.log(
    `ADS GROWTH server running on port ${PORT}`
  );
});
