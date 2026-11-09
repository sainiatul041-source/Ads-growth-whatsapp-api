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

const required = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SUPABASE_ANON_KEY",
  "JWT_SECRET"
];

for (const name of required) {
  if (!process.env[name]) {
    console.error("Missing environment variable:", name);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

const authClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

const prices = {
  Starter: 4999,
  Business: 7999,
  Enterprise: 9999
};

app.use(helmet({ crossOriginResourcePolicy: false }));

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
  : true;

app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "100kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and WEBP files are allowed."));
    }

    cb(null, true);
  }
});

function fail(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function serverError(res, error) {
  console.error("SERVER ERROR:", error);
  return fail(res, 500, "Server error. Check Render logs.");
}

function createToken(id, role) {
  return jwt.sign(
    { id, role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

/*
  AUTHENTICATION SUPPORT:
  1. Our own ADS GROWTH JWT (client/admin)
  2. Supabase Auth access token (Admin Page)

  Supabase tokens are accepted only if the user is
  present in public.admin_users.
*/
async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";

  if (!token) {
    return fail(res, 401, "Please login first.");
  }

  // First try ADS GROWTH JWT
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded && decoded.id && decoded.role) {
      req.user = decoded;
      return next();
    }
  } catch (error) {
    // Not our JWT; try Supabase access token below.
  }

  // Then try Supabase Auth access token
  try {
    const { data, error } = await authClient.auth.getUser(token);

    if (error || !data || !data.user) {
      return fail(res, 401, "Invalid or expired login session.");
    }

    const { data: admin, error: adminError } = await supabase
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) {
      console.error("Admin verification error:", adminError);
      return fail(res, 500, "Could not verify admin account.");
    }

    if (!admin) {
      return fail(res, 403, "Admin access required.");
    }

    req.user = {
      id: data.user.id,
      email: data.user.email,
      role: "admin"
    };

    return next();
  } catch (error) {
    console.error("Authentication error:", error);
    return fail(res, 401, "Could not verify login session.");
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return fail(res, 403, "Admin access required.");
  }
  next();
}

function clientOnly(req, res, next) {
  if (!req.user || req.user.role !== "client") {
    return fail(res, 403, "Client access required.");
  }
  next();
}

async function getActiveClient(id) {
  const { data, error } = await supabase
    .from("customers")
    .select("id,status")
    .eq("id", id)
    .maybeSingle();

  if (error || !data || data.status !== "approved") {
    return null;
  }

  return data;
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH",
    status: "running"
  });
});

/* CUSTOMER REGISTRATION */
app.post("/api/register", async (req, res) => {
  try {
    const {
      full_name,
      phone,
      email,
      plan,
      amount
    } = req.body || {};

    if (
      !full_name ||
      !phone ||
      !prices[plan] ||
      Number(amount) !== prices[plan]
    ) {
      return fail(res, 400, "Invalid registration details.");
    }

    const cleanName = String(full_name).trim();
    const cleanPhone = String(phone).trim();
    const cleanEmail = email ? String(email).trim() : null;

    if (!cleanName || cleanName.length > 100) {
      return fail(res, 400, "Invalid name.");
    }

    if (!/^[0-9+\-\s]{10,15}$/.test(cleanPhone)) {
      return fail(res, 400, "Invalid mobile number.");
    }

    const { data, error } = await supabase
      .from("customers")
      .insert({
        full_name: cleanName,
        phone: cleanPhone,
        email: cleanEmail,
        plan,
        amount: prices[plan],
        status: "pending"
      })
      .select("id")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      customer: { id: data.id },
      message: "Registration successful."
    });
  } catch (error) {
    return serverError(res, error);
  }
});

/* PAYMENT SUBMISSION */
app.post(
  "/api/payment-submit",
  upload.single("screenshot"),
  async (req, res) => {
    let uploadedPath = null;

    try {
      const { customer_id, phone, utr } = req.body || {};

      if (!customer_id || !phone || !utr || !req.file) {
        return fail(res, 400, "All payment details are required.");
      }

      const cleanUtr = String(utr).trim();

      if (!/^[A-Za-z0-9]{6,30}$/.test(cleanUtr)) {
        return fail(res, 400, "Invalid UTR.");
      }

      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id,phone,status")
        .eq("id", customer_id)
        .maybeSingle();

      if (customerError || !customer) {
        return fail(res, 404, "Customer not found.");
      }

      if (customer.phone.trim() !== String(phone).trim()) {
        return fail(res, 400, "Registered mobile number does not match.");
      }

      const { data: duplicate, error: duplicateError } = await supabase
        .from("payments")
        .select("id")
        .ilike("utr", cleanUtr)
        .maybeSingle();

      if (duplicateError) throw duplicateError;

      if (duplicate) {
        return fail(res, 409, "This UTR has already been submitted.");
      }

      const extension = {
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp"
      }[req.file.mimetype];

      if (!extension) {
        return fail(res, 400, "Only JPG, PNG and WEBP are allowed.");
      }

      uploadedPath = `${crypto.randomUUID()}.${extension}`;

      const { error: storageError } = await supabase.storage
        .from("payment-screenshots")
        .upload(uploadedPath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (storageError) throw storageError;

      const { data: payment, error } = await supabase
        .from("payments")
        .insert({
          customer_id,
          utr: cleanUtr,
          screenshot_path: uploadedPath,
          status: "pending"
        })
        .select("id")
        .single();

      if (error) throw error;

      return res.json({
        success: true,
        payment: { id: payment.id },
        message: "Payment submitted. Waiting for manual verification."
      });
    } catch (error) {
      if (uploadedPath) {
        await supabase.storage
          .from("payment-screenshots")
          .remove([uploadedPath]);
      }

      return serverError(res, error);
    }
  }
);

/* ADMIN LOGIN */
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return fail(res, 400, "Email and password are required.");
    }

    const { data, error } = await authClient.auth.signInWithPassword({
      email: String(email).trim(),
      password: String(password)
    });

    if (error || !data.user) {
      return fail(res, 401, "Invalid admin login.");
    }

    const { data: admin, error: adminError } = await supabase
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) throw adminError;

    if (!admin) {
      return fail(res, 403, "This user is not an authorized admin.");
    }

    return res.json({
      success: true,
      token: createToken(data.user.id, "admin"),
      admin: {
        id: data.user.id,
        email: data.user.email
      }
    });
  } catch (error) {
    return serverError(res, error);
  }
});

/* ADMIN SESSION CHECK - REQUIRED BY ADMIN PAGE */
app.get("/api/admin/me", authenticate, adminOnly, async (req, res) => {
  try {
    const { data: admin, error } = await supabase
      .from("admin_users")
      .select("user_id")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) throw error;

    if (!admin) {
      return fail(res, 403, "Admin access has been removed.");
    }

    return res.json({
      success: true,
      admin: {
        id: req.user.id,
        email: req.user.email || null
      }
    });
  } catch (error) {
    return serverError(res, error);
  }
});

/* ADMIN: CUSTOMER LIST */
app.get(
  "/api/admin/customers",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("customers")
        .select("id,full_name,phone,email,plan,amount,status,created_at")
        .order("created_at", { ascending: false });

      if (error) throw error;

      return res.json({ success: true, customers: data });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN: PAYMENT LIST */
app.get(
  "/api/admin/payments",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("payments")
        .select("id,customer_id,utr,screenshot_path,status,created_at,verified_at")
        .order("created_at", { ascending: false });

      if (error) throw error;

      return res.json({ success: true, payments: data });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN: PAYMENT SCREENSHOT */
app.get(
  "/api/admin/payment-image/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data: payment, error } = await supabase
        .from("payments")
        .select("screenshot_path")
        .eq("id", req.params.id)
        .maybeSingle();

      if (error) throw error;
      if (!payment) return fail(res, 404, "Payment not found.");

      const { data, error: urlError } = await supabase.storage
        .from("payment-screenshots")
        .createSignedUrl(payment.screenshot_path, 60);

      if (urlError) throw urlError;

      return res.json({
        success: true,
        url: data.signedUrl
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN: APPROVE PAYMENT AND CREATE CLIENT LOGIN/API KEY */
app.post(
  "/api/admin/approve/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data: payment, error: paymentError } = await supabase
        .from("payments")
        .select("id,customer_id,status")
        .eq("id", req.params.id)
        .maybeSingle();

      if (paymentError) throw paymentError;
      if (!payment) return fail(res, 404, "Payment not found.");

      if (payment.status === "approved") {
        return fail(res, 409, "Payment is already approved.");
      }

      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id,password_hash")
        .eq("id", payment.customer_id)
        .maybeSingle();

      if (customerError) throw customerError;
      if (!customer) return fail(res, 404, "Customer not found.");

      const { data: activeKeys, error: keyReadError } = await supabase
        .from("api_keys")
        .select("id")
        .eq("customer_id", customer.id)
        .eq("status", "active");

      if (keyReadError) throw keyReadError;

      let temporaryPassword = null;
      let rawKey = null;

      if (!customer.password_hash) {
        temporaryPassword = crypto.randomBytes(12).toString("base64url");

        const passwordHash = await bcrypt.hash(temporaryPassword, 12);

        const { error } = await supabase
          .from("customers")
          .update({ password_hash: passwordHash })
          .eq("id", customer.id);

        if (error) throw error;
      }

      if (!activeKeys || activeKeys.length === 0) {
        rawKey = "ag_live_" + crypto.randomBytes(32).toString("hex");

        const keyHash = crypto
          .createHash("sha256")
          .update(rawKey)
          .digest("hex");

        const { error } = await supabase
          .from("api_keys")
          .insert({
            customer_id: customer.id,
            key_hash: keyHash,
            key_prefix: rawKey.slice(0, 15),
            status: "active"
          });

        if (error) throw error;
      }

      const { error: customerUpdateError } = await supabase
        .from("customers")
        .update({ status: "approved" })
        .eq("id", customer.id);

      if (customerUpdateError) throw customerUpdateError;

      const { error: paymentUpdateError } = await supabase
        .from("payments")
        .update({
          status: "approved",
          verified_at: new Date().toISOString()
        })
        .eq("id", payment.id);

      if (paymentUpdateError) throw paymentUpdateError;

      return res.json({
        success: true,
        message: "Client approved successfully.",
        customer_id: customer.id,
        temporary_password: temporaryPassword,
        api_key: rawKey,
        note: "Save credentials securely. They are not shown again."
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN: REJECT PAYMENT */
app.post(
  "/api/admin/reject/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("payments")
        .update({ status: "rejected" })
        .eq("id", req.params.id);

      if (error) throw error;

      return res.json({
        success: true,
        message: "Payment rejected."
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* CLIENT LOGIN */
app.post("/api/client/login", async (req, res) => {
  try {
    const { customer_id, password } = req.body || {};

    if (!customer_id || !password) {
      return fail(res, 400, "Customer ID and password are required.");
    }

    const { data: customer, error } = await supabase
      .from("customers")
      .select("id,password_hash,status")
      .eq("id", customer_id)
      .maybeSingle();

    if (
      error ||
      !customer ||
      customer.status !== "approved" ||
      !customer.password_hash
    ) {
      return fail(res, 401, "Client not approved or login not set up.");
    }

    const valid = await bcrypt.compare(
      String(password),
      customer.password_hash
    );

    if (!valid) {
      return fail(res, 401, "Incorrect password.");
    }

    return res.json({
      success: true,
      token: createToken(customer.id, "client")
    });
  } catch (error) {
    return serverError(res, error);
  }
});

/* CLIENT DASHBOARD */
app.get(
  "/api/client/dashboard",
  authenticate,
  clientOnly,
  async (req, res) => {
    try {
      const customer = await getActiveClient(req.user.id);

      if (!customer) {
        return fail(res, 403, "Client access is disabled.");
      }

      const { data: profile, error } = await supabase
        .from("customers")
        .select("id,full_name,phone,email,plan,amount,status,created_at")
        .eq("id", req.user.id)
        .single();

      if (error) throw error;

      const { data: keys, error: keyError } = await supabase
        .from("api_keys")
        .select("id,key_prefix,status,created_at")
        .eq("customer_id", req.user.id)
        .order("created_at", { ascending: false });

      if (keyError) throw keyError;

      return res.json({
        success: true,
        customer: profile,
        api_keys: keys
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* CLIENT: REVOKE OWN API KEY */
app.post(
  "/api/client/revoke-key/:id",
  authenticate,
  clientOnly,
  async (req, res) => {
    try {
      const { data: key, error: findError } = await supabase
        .from("api_keys")
        .select("id")
        .eq("id", req.params.id)
        .eq("customer_id", req.user.id)
        .eq("status", "active")
        .maybeSingle();

      if (findError) throw findError;
      if (!key) return fail(res, 404, "Active key not found.");

      const { error } = await supabase
        .from("api_keys")
        .update({ status: "revoked" })
        .eq("id", key.id);

      if (error) throw error;

      return res.json({
        success: true,
        message: "API key revoked."
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* API KEY VALIDATION ONLY - DOES NOT SEND WHATSAPP MESSAGES */
app.post("/api/key/validate", async (req, res) => {
  try {
    const rawKey = String((req.body || {}).api_key || "");

    if (!rawKey.startsWith("ag_live_")) {
      return fail(res, 401, "Invalid API key.");
    }

    const keyHash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const { data: key, error } = await supabase
      .from("api_keys")
      .select("customer_id,status")
      .eq("key_hash", keyHash)
      .eq("status", "active")
      .maybeSingle();

    if (error) throw error;
    if (!key) return fail(res, 401, "Invalid or revoked API key.");

    const customer = await getActiveClient(key.customer_id);

    if (!customer) {
      return fail(res, 403, "Client is not active.");
    }

    return res.json({
      success: true,
      message: "API key is valid.",
      customer_id: key.customer_id
    });
  } catch (error) {
    return serverError(res, error);
  }
});

/* MULTER / UPLOAD ERROR HANDLER */
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    return fail(res, 400, "File upload error: " + error.message);
  }

  if (error) {
    return fail(res, 400, error.message || "Request error.");
  }

  next();
});

app.listen(PORT, () => {
  console.log("ADS GROWTH server running on port " + PORT);
});
