
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
  origin: [
    "https://sainiatul041-source.github.io",
    "http://localhost:3000"
  ],
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
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (allowed.includes(file.mimetype)) {
      return cb(null, true);
    }

    cb(new Error("Only JPG, PNG and WEBP images allowed."));
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
  return jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function bearer(req) {
  const header = req.headers.authorization || "";

  return header.startsWith("Bearer ")
    ? header.slice(7)
    : "";
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
  const parts = String(value || "").split(":");

  if (parts.length !== 3) {
    throw new Error("Invalid encrypted value.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(parts[0], "hex")
  );

  decipher.setAuthTag(Buffer.from(parts[1], "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(parts[2], "hex")),
    decipher.final()
  ]).toString("utf8");
}

// ADMIN AUTHENTICATION
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
      return fail(res, "Admin access denied.", 403);
    }

    req.admin = decoded;
    next();
  } catch {
    return fail(res, "Admin login required.", 401);
  }
}

// CLIENT AUTHENTICATION
function clientAuth(req, res, next) {
  try {
    const decoded = jwt.verify(
      bearer(req),
      process.env.JWT_SECRET
    );

    if (decoded.role !== "client" || !decoded.id) {
      return fail(res, "Client access denied.", 403);
    }

    req.client = decoded;
    next();
  } catch {
    return fail(res, "Client login required.", 401);
  }
}

// CHECK CLIENT APPROVAL
async function approvedCustomer(req, res, next) {
  try {
    const { data, error } = await db
      .from("customers")
      .select("id,status")
      .eq("id", req.client.id)
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return fail(res, "Client account not found.", 404);
    }

    if (data.status !== "approved") {
      return fail(
        res,
        "Your account is waiting for admin approval.",
        403
      );
    }

    next();
  } catch (error) {
    next(error);
  }
}

// DATABASE HELPERS
async function getCustomer(id) {
  const { data, error } = await db
    .from("customers")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) throw error;
  return data;
}

async function getCustomerByLogin(login, password) {
  const value = String(login || "").trim();

  let query = db
    .from("customers")
    .select("*");

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

// CLIENT REGISTRATION
app.post(
  "/api/register",
  limiter,
  asyncRoute(async (req, res) => {
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

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();

    if (cleanName.length < 2) {
      return fail(res, "Please enter a valid name.");
    }

    if (String(password).length < 8) {
      return fail(res, "Password must be at least 8 characters.");
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return fail(res, "Enter a valid email address.");
    }

    if (!/^[0-9+\-\s]{8,20}$/.test(cleanPhone)) {
      return fail(res, "Enter a valid phone number.");
    }

    const { data: existing, error: checkError } = await db
      .from("customers")
      .select("id")
      .or(
        `email.eq.${cleanEmail},phone.eq.${cleanPhone}`
      )
      .limit(1);

    if (checkError) throw checkError;

    if (existing && existing.length) {
      return fail(
        res,
        "Email or phone already registered.",
        409
      );
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
      .select("id,name,full_name,email,phone,business_name,plan,amount,status,created_at")
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      message: "Account created. Please complete UPI payment.",
      customer: data,
      next_step: "payment"
    });
  })
);

// CLIENT LOGIN
app.post(
  "/api/client/login",
  limiter,
  asyncRoute(async (req, res) => {
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

    const customer = await getCustomerByLogin(
      login,
      password
    );

    if (!customer) {
      return fail(res, "Invalid login details.", 401);
    }

    const token = signToken({
      role: "client",
      id: customer.id,
      email: customer.email
    });

    return res.json({
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
      },
      message: customer.status === "approved"
        ? "Login successful."
        : "Login successful. Complete payment and wait for approval."
    });
  })
);

// CLIENT PROFILE
app.get(
  "/api/client/me",
  clientAuth,
  asyncRoute(async (req, res) => {
    const customer = await getCustomer(req.client.id);

    if (!customer) {
      return fail(res, "Client not found.", 404);
    }

    const {
      password_hash,
      ...safeCustomer
    } = customer;

    return res.json({
      success: true,
      customer: safeCustomer
    });
  })
);

// ADMIN LOGIN
app.post(
  "/api/admin/login",
  limiter,
  asyncRoute(async (req, res) => {
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

    const { data: adminRecord, error: adminError } = await db
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError) throw adminError;

    if (!adminRecord) {
      return fail(res, "Admin access is not configured.", 403);
    }

    const token = signToken({
      role: "admin",
      email: ADMIN_EMAIL,
      user_id: data.user.id
    });

    return res.json({
      success: true,
      token,
      admin: { email: ADMIN_EMAIL }
    });
  })
);

// ADMIN PROFILE
app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    admin: { email: ADMIN_EMAIL }
  });
});

// PART 1 ENDS HERE.
// PART 2 WILL CONTINUE BELOW.
// Do not add app.listen() yet.
// ==========================================
// PART 2 - UPI PAYMENT MANAGEMENT
// ==========================================

const UPI_ID = process.env.UPI_ID || "";
const UPI_NAME = process.env.UPI_NAME || "ADS GROWTH";
const PAYMENT_AMOUNT = 7999;
const PAYMENT_BUCKET = "payment-proofs";

// CLIENT PAYMENT DETAILS
app.get(
  "/api/payment/details",
  clientAuth,
  asyncRoute(async (req, res) => {
    const customer = await getCustomer(req.client.id);

    if (!customer) {
      return fail(res, "Client account not found.", 404);
    }

    if (!UPI_ID) {
      return fail(
        res,
        "UPI payment is not configured. Please contact support.",
        503
      );
    }

    return res.json({
      success: true,
      amount: PAYMENT_AMOUNT,
      currency: "INR",
      payment_method: "UPI",
      upi_id: UPI_ID,
      payee_name: UPI_NAME,
      plan: "Business",
      customer_status: customer.status
    });
  })
);

// CLIENT SUBMITS PAYMENT
app.post(
  "/api/payment/submit",
  clientAuth,
  limiter,
  upload.single("proof"),
  asyncRoute(async (req, res) => {
    const customer = await getCustomer(req.client.id);

    if (!customer) {
      return fail(res, "Client account not found.", 404);
    }

    if (customer.status === "approved") {
      return fail(res, "Your account is already approved.");
    }

    const utr = String(req.body.utr || "").trim();

    if (!/^[A-Za-z0-9]{8,30}$/.test(utr)) {
      return fail(res, "Please enter a valid UTR / Transaction ID.");
    }

    if (!req.file) {
      return fail(res, "Payment screenshot is required.");
    }

    const { data: duplicate, error: duplicateError } = await db
      .from("payments")
      .select("id")
      .eq("utr", utr)
      .limit(1);

    if (duplicateError) throw duplicateError;

    if (duplicate && duplicate.length) {
      return fail(res, "This transaction ID has already been submitted.", 409);
    }

    const extensionMap = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp"
    };

    const extension = extensionMap[req.file.mimetype];

    if (!extension) {
      return fail(res, "Invalid screenshot format.");
    }

    const filePath =
      `${req.client.id}/${crypto.randomUUID()}.${extension}`;

    const { error: uploadError } = await db.storage
      .from(PAYMENT_BUCKET)
      .upload(filePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) throw uploadError;

    const { data: payment, error: paymentError } = await db
      .from("payments")
      .insert({
        customer_id: req.client.id,
        amount: PAYMENT_AMOUNT,
        payment_method: "UPI",
        utr,
        screenshot_path: filePath,
        status: "pending"
      })
      .select("id,customer_id,amount,payment_method,utr,screenshot_path,status,created_at")
      .single();

    if (paymentError) {
      await db.storage
        .from(PAYMENT_BUCKET)
        .remove([filePath]);

      throw paymentError;
    }

    return res.status(201).json({
      success: true,
      message: "Payment submitted. Please wait for admin verification.",
      payment: {
        id: payment.id,
        amount: payment.amount,
        utr: payment.utr,
        status: payment.status
      }
    });
  })
);

// CLIENT PAYMENT HISTORY
app.get(
  "/api/payment/history",
  clientAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("payments")
      .select("id,amount,payment_method,utr,status,created_at,verified_at,rejection_reason")
      .eq("customer_id", req.client.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({
      success: true,
      payments: data || []
    });
  })
);

// ADMIN: VIEW ALL PAYMENTS
app.get(
  "/api/admin/payments",
  adminAuth,
  asyncRoute(async (req, res) => {
    const status = String(req.query.status || "").trim();

    let query = db
      .from("payments")
      .select("*")
      .order("created_at", { ascending: false });

    if (["pending", "approved", "rejected"].includes(status)) {
      query = query.eq("status", status);
    }

    const { data: payments, error } = await query;

    if (error) throw error;

    const customerIds = [
      ...new Set((payments || []).map(p => p.customer_id))
    ];

    let customers = [];

    if (customerIds.length) {
      const result = await db
        .from("customers")
        .select("id,full_name,name,email,phone,business_name,status")
        .in("id", customerIds);

      if (result.error) throw result.error;
      customers = result.data || [];
    }

    const customerMap = new Map(
      customers.map(c => [String(c.id), c])
    );

    const resultPayments = (payments || []).map(payment => ({
      ...payment,
      customer: customerMap.get(String(payment.customer_id)) || null
    }));

    return res.json({
      success: true,
      count: resultPayments.length,
      payments: resultPayments
    });
  })
);

// ADMIN: VIEW PRIVATE PAYMENT SCREENSHOT
app.get(
  "/api/admin/payments/:id/proof",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data: payment, error } = await db
      .from("payments")
      .select("id,screenshot_path")
      .eq("id", req.params.id)
      .maybeSingle();

    if (error) throw error;

    if (!payment || !payment.screenshot_path) {
      return fail(res, "Payment screenshot not found.", 404);
    }

    const { data, error: signedError } = await db.storage
      .from(PAYMENT_BUCKET)
      .createSignedUrl(payment.screenshot_path, 300);

    if (signedError) throw signedError;

    return res.json({
      success: true,
      url: data.signedUrl,
      expires_in_seconds: 300
    });
  })
);

// ADMIN: APPROVE OR REJECT PAYMENT
app.post(
  "/api/admin/payments/:id/review",
  adminAuth,
  asyncRoute(async (req, res) => {
    const action = String(req.body.action || "").toLowerCase();
    const reason = String(req.body.reason || "").trim();

    if (!["approve", "reject"].includes(action)) {
      return fail(res, "Action must be approve or reject.");
    }

    const { data: payment, error: paymentReadError } = await db
      .from("payments")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();

    if (paymentReadError) throw paymentReadError;

    if (!payment) {
      return fail(res, "Payment not found.", 404);
    }

    if (payment.status !== "pending") {
      return fail(res, "This payment has already been reviewed.");
    }

    const newStatus = action === "approve"
      ? "approved"
      : "rejected";

    const { data: updatedPayment, error: updateError } = await db
      .from("payments")
      .update({
        status: newStatus,
        verified_at: new Date().toISOString(),
        rejection_reason: action === "reject" ? reason : null
      })
      .eq("id", payment.id)
      .eq("status", "pending")
      .select("*")
      .maybeSingle();

    if (updateError) throw updateError;

    if (!updatedPayment) {
      return fail(res, "Payment review conflict. Refresh and try again.", 409);
    }

    if (action === "approve") {
      const { error: customerError } = await db
        .from("customers")
        .update({ status: "approved" })
        .eq("id", payment.customer_id);

      if (customerError) {
        await db
          .from("payments")
          .update({
            status: "pending",
            verified_at: null
          })
          .eq("id", payment.id);

        throw customerError;
      }
    }

    return res.json({
      success: true,
      message: action === "approve"
        ? "Payment approved. Client account is now approved."
        : "Payment rejected.",
      payment: updatedPayment
    });
  })
);

// ADMIN: PAYMENT SUMMARY
app.get(
  "/api/admin/payment-summary",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("payments")
      .select("status,amount");

    if (error) throw error;

    const summary = {
      total: (data || []).length,
      pending: 0,
      approved: 0,
      rejected: 0,
      approved_amount: 0
    };

    for (const payment of data || []) {
      if (summary[payment.status] !== undefined) {
        summary[payment.status]++;
      }

      if (payment.status === "approved") {
        summary.approved_amount += Number(payment.amount || 0);
      }
    }

    return res.json({
      success: true,
      summary
    });
  })
);

// PART 2 ENDS HERE.
// PART 3 WILL CONTINUE BELOW.
  
// ==========================================
// PART 3 - ADMIN + API KEY MANAGEMENT
// ==========================================

// ADMIN: ALL CLIENTS
app.get(
  "/api/admin/clients",
  adminAuth,
  asyncRoute(async (req, res) => {
    const status = String(req.query.status || "").trim();

    let query = db
      .from("customers")
      .select("id,name,full_name,email,phone,business_name,plan,amount,status,created_at")
      .order("created_at", { ascending: false });

    if (["pending", "approved", "rejected"].includes(status)) {
      query = query.eq("status", status);
    }

    const { data, error } = await query;

    if (error) throw error;

    return res.json({
      success: true,
      count: (data || []).length,
      clients: data || []
    });
  })
);

// ADMIN: SINGLE CLIENT DETAILS
app.get(
  "/api/admin/clients/:id",
  adminAuth,
  asyncRoute(async (req, res) => {
    const customer = await getCustomer(req.params.id);

    if (!customer) {
      return fail(res, "Client not found.", 404);
    }

    const {
      password_hash,
      ...safeCustomer
    } = customer;

    const { data: payments, error: paymentError } = await db
      .from("payments")
      .select("id,amount,payment_method,utr,status,created_at,verified_at")
      .eq("customer_id", req.params.id)
      .order("created_at", { ascending: false });

    if (paymentError) throw paymentError;

    const { data: keys, error: keyError } = await db
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("customer_id", req.params.id)
      .order("created_at", { ascending: false });

    if (keyError) throw keyError;

    return res.json({
      success: true,
      client: safeCustomer,
      payments: payments || [],
      api_keys: keys || []
    });
  })
);

// ADMIN: MANUAL CLIENT APPROVAL / REJECTION
app.post(
  "/api/admin/clients/:id/status",
  adminAuth,
  asyncRoute(async (req, res) => {
    const status = String(req.body.status || "").toLowerCase();

    if (!["approved", "rejected", "pending"].includes(status)) {
      return fail(res, "Invalid client status.");
    }

    const customer = await getCustomer(req.params.id);

    if (!customer) {
      return fail(res, "Client not found.", 404);
    }

    // Approval must follow verified payment.
    if (status === "approved") {
      const { data: verifiedPayment, error } = await db
        .from("payments")
        .select("id")
        .eq("customer_id", req.params.id)
        .eq("status", "approved")
        .limit(1)
        .maybeSingle();

      if (error) throw error;

      if (!verifiedPayment) {
        return fail(
          res,
          "Verify a payment before approving this client."
        );
      }
    }

    const { data, error } = await db
      .from("customers")
      .update({ status })
      .eq("id", req.params.id)
      .select("id,name,full_name,email,status")
      .single();

    if (error) throw error;

    return res.json({
      success: true,
      message: "Client status updated.",
      client: data
    });
  })
);

// ADMIN: DASHBOARD SUMMARY
app.get(
  "/api/admin/dashboard",
  adminAuth,
  asyncRoute(async (req, res) => {
    const [clientsResult, paymentsResult, keysResult] =
      await Promise.all([
        db.from("customers").select("id,status"),
        db.from("payments").select("id,status,amount"),
        db.from("api_keys").select("id,status")
      ]);

    if (clientsResult.error) throw clientsResult.error;
    if (paymentsResult.error) throw paymentsResult.error;
    if (keysResult.error) throw keysResult.error;

    const clients = clientsResult.data || [];
    const payments = paymentsResult.data || [];
    const keys = keysResult.data || [];

    return res.json({
      success: true,
      summary: {
        total_clients: clients.length,
        pending_clients: clients.filter(x => x.status === "pending").length,
        approved_clients: clients.filter(x => x.status === "approved").length,
        rejected_clients: clients.filter(x => x.status === "rejected").length,
        total_payments: payments.length,
        pending_payments: payments.filter(x => x.status === "pending").length,
        approved_payments: payments.filter(x => x.status === "approved").length,
        approved_revenue: payments
          .filter(x => x.status === "approved")
          .reduce((sum, x) => sum + Number(x.amount || 0), 0),
        total_api_keys: keys.length,
        active_api_keys: keys.filter(x => x.status === "active").length
      }
    });
  })
);

// ADMIN: CREATE CLIENT API KEY
app.post(
  "/api/admin/clients/:id/api-keys",
  adminAuth,
  asyncRoute(async (req, res) => {
    const customer = await getCustomer(req.params.id);

    if (!customer) {
      return fail(res, "Client not found.", 404);
    }

    if (customer.status !== "approved") {
      return fail(
        res,
        "Client must be approved before API creation."
      );
    }

    const { data: verifiedPayment, error: paymentError } = await db
      .from("payments")
      .select("id")
      .eq("customer_id", req.params.id)
      .eq("status", "approved")
      .limit(1)
      .maybeSingle();

    if (paymentError) throw paymentError;

    if (!verifiedPayment) {
      return fail(res, "Verified payment required.");
    }

    const name = String(req.body.name || "ADS GROWTH API").trim();

    if (name.length > 80) {
      return fail(res, "API name is too long.");
    }

    const rawKey =
      "adsg_" + crypto.randomBytes(32).toString("hex");

    const keyHash = crypto
      .createHash("sha256")
      .update(rawKey)
      .digest("hex");

    const encryptedKey = encrypt(rawKey);
    const keyPrefix = rawKey.slice(0, 12);

    const { data, error } = await db
      .from("api_keys")
      .insert({
        customer_id: req.params.id,
        name,
        key_hash: keyHash,
        encrypted_key: encryptedKey,
        key_prefix: keyPrefix,
        status: "active"
      })
      .select("id,name,key_prefix,status,created_at")
      .single();

    if (error) throw error;

    // Full key is returned only once to the admin.
    return res.status(201).json({
      success: true,
      message: "Client API key created. Save this key securely.",
      api_key: rawKey,
      details: data
    });
  })
);

// ADMIN: LIST CLIENT API KEYS
app.get(
  "/api/admin/clients/:id/api-keys",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("customer_id", req.params.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({
      success: true,
      api_keys: data || []
    });
  })
);

// ADMIN: REVOKE API KEY
app.post(
  "/api/admin/api-keys/:id/revoke",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", req.params.id)
      .eq("status", "active")
      .select("id,name,key_prefix,status")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return fail(res, "Active API key not found.", 404);
    }

    return res.json({
      success: true,
      message: "API key revoked successfully.",
      api_key: data
    });
  })
);

// CLIENT: VIEW OWN API KEYS
app.get(
  "/api/client/api-keys",
  clientAuth,
  approvedCustomer,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("customer_id", req.client.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    return res.json({
      success: true,
      api_keys: data || [],
      message: "Contact admin if you need a new API key."
    });
  })
);

// CLIENT: VIEW OWN API KEY DETAILS
app.get(
  "/api/client/api-keys/:id",
  clientAuth,
  approvedCustomer,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("api_keys")
      .select("id,name,key_prefix,status,created_at")
      .eq("id", req.params.id)
      .eq("customer_id", req.client.id)
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return fail(res, "API key not found.", 404);
    }

    return res.json({
      success: true,
      api_key: data,
      message: "The complete API key is shown to the admin only. Ask admin for secure delivery."
    });
  })
);

// PART 3 ENDS HERE.
// PART 4 WILL CONTINUE BELOW.
  // ==========================================
// PART 4/4 — API KEY + WHATSAPP + SERVER START
// ==========================================

// Authenticate ADS GROWTH platform API key
async function platformApiAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const apiKey = authHeader.replace(/^Bearer\s+/i, "").trim();

    if (!apiKey || !apiKey.startsWith("adsg_")) {
      return fail(res, 401, "Valid API key required");
    }

    const keyHash = crypto
      .createHash("sha256")
      .update(apiKey)
      .digest("hex");

    const { data: keyRow, error } = await db
      .from("api_keys")
      .select("id, customer_id, status")
      .eq("key_hash", keyHash)
      .eq("status", "active")
      .maybeSingle();

    if (error) throw error;
    if (!keyRow) return fail(res, 401, "Invalid or revoked API key");

    const customer = await getCustomer(keyRow.customer_id);

    if (!customer || customer.status !== "approved") {
      return fail(res, 403, "Client account is not approved");
    }

    req.apiCustomer = customer;
    req.apiKeyRecord = keyRow;

    next();
  } catch (error) {
    console.error("Platform API auth:", error);
    return fail(res, 500, "API authentication failed");
  }
}

// Test endpoint for ADS GROWTH API customers
app.get("/api/v1/profile", platformApiAuth, (req, res) => {
  res.json({
    success: true,
    customer: {
      id: req.apiCustomer.id,
      name: req.apiCustomer.full_name,
      business_name: req.apiCustomer.business_name,
      plan: req.apiCustomer.plan,
      status: req.apiCustomer.status
    }
  });
});

// Admin adds or updates client's WhatsApp connection
app.post(
  "/api/admin/clients/:id/whatsapp",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { phone_number_id, waba_id, access_token } = req.body;

    if (!phone_number_id || !waba_id || !access_token) {
      return fail(res, 400, "Phone Number ID, WABA ID and Access Token required");
    }

    const customer = await getCustomer(req.params.id);

    if (!customer) return fail(res, 404, "Client not found");

    const encryptedToken = encrypt(access_token);

    const { data, error } = await db
      .from("whatsapp_connections")
      .upsert({
        customer_id: customer.id,
        phone_number_id: String(phone_number_id).trim(),
        waba_id: String(waba_id).trim(),
        access_token_encrypted: encryptedToken,
        status: "active",
        updated_at: new Date().toISOString()
      }, {
        onConflict: "customer_id"
      })
      .select("id, customer_id, phone_number_id, waba_id, status")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "WhatsApp connection saved",
      connection: data
    });
  })
);

// Admin checks client's WhatsApp connection
app.get(
  "/api/admin/clients/:id/whatsapp",
  adminAuth,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("whatsapp_connections")
      .select("id, customer_id, phone_number_id, waba_id, status, updated_at")
      .eq("customer_id", req.params.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      success: true,
      connection: data || null
    });
  })
);

// Client checks WhatsApp connection status
app.get(
  "/api/client/whatsapp",
  clientAuth,
  approvedCustomer,
  asyncRoute(async (req, res) => {
    const { data, error } = await db
      .from("whatsapp_connections")
      .select("phone_number_id, waba_id, status, updated_at")
      .eq("customer_id", req.customer.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      success: true,
      connected: Boolean(data && data.status === "active"),
      connection: data || null
    });
  })
);

// Send a WhatsApp text message using the connected Meta account
app.post(
  "/api/v1/whatsapp/send",
  platformApiAuth,
  limiter,
  asyncRoute(async (req, res) => {
    const { to, message } = req.body;

    const recipient = String(to || "").replace(/[+\s()-]/g, "");
    const textMessage = String(message || "").trim();

    if (!/^[1-9]\d{7,14}$/.test(recipient)) {
      return fail(res, 400, "Recipient must be a valid international phone number");
    }

    if (!textMessage || textMessage.length > 4096) {
      return fail(res, 400, "Message is required and must be under 4096 characters");
    }

    const { data: connection, error } = await db
      .from("whatsapp_connections")
      .select("phone_number_id, access_token_encrypted, status")
      .eq("customer_id", req.apiCustomer.id)
      .eq("status", "active")
      .maybeSingle();

    if (error) throw error;

    if (!connection) {
      return fail(res, 403, "WhatsApp account is not connected. Contact admin.");
    }

    const accessToken = decrypt(connection.access_token_encrypted);

    const metaResponse = await fetch(
      `https://graph.facebook.com/v23.0/${encodeURIComponent(connection.phone_number_id)}/messages`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          recipient_type: "individual",
          to: recipient,
          type: "text",
          text: {
            preview_url: false,
            body: textMessage
          }
        })
      }
    );

    const metaResult = await metaResponse.json();

    if (!metaResponse.ok) {
      console.error("Meta WhatsApp API error:", metaResult);
      return res.status(502).json({
        success: false,
        message: "Meta WhatsApp API rejected the request",
        error: metaResult.error?.message || "Message could not be sent"
      });
    }

    res.json({
      success: true,
      message: "WhatsApp message accepted by Meta",
      result: metaResult
    });
  })
);

// Default 404
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found"
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) return next(error);

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`ADS GROWTH API running on port ${PORT}`);
});         
