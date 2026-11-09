
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
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const authClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const prices = {
  Starter: 4999,
  Business: 7999,
  Enterprise: 9999
};

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true,
  methods: ["GET", "POST", "PATCH", "OPTIONS"],
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
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter(req, file, cb) {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error("Only JPG, PNG and WEBP files are allowed.")
      );
    }

    cb(null, true);
  }
});

/* COMMON FUNCTIONS */

function fail(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function serverError(res, error) {
  console.error("SERVER ERROR:", error);

  return fail(
    res,
    500,
    "Server error. Please check Render logs."
  );
}

function createToken(id, role) {
  return jwt.sign(
    { id, role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function generateApiKey() {
  return "ag_live_" + crypto.randomBytes(32).toString("hex");
}

function hashApiKey(key) {
  return crypto
    .createHash("sha256")
    .update(key)
    .digest("hex");
}

async function getActiveKey(customerId) {
  const { data, error } = await supabase
    .from("api_keys")
    .select("id,key_prefix,status,created_at")
    .eq("customer_id", customerId)
    .eq("status", "active")
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw error;
  return data;
}

/* AUTHENTICATION */

async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7).trim()
    : "";

  if (!token) {
    return fail(res, 401, "Please login first.");
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (
      decoded.id &&
      ["admin", "client"].includes(decoded.role)
    ) {
      req.user = decoded;
      return next();
    }
  } catch (error) {
    // Try Supabase admin session below.
  }

  try {
    const { data, error } =
      await authClient.auth.getUser(token);

    if (error || !data.user) {
      return fail(res, 401, "Invalid or expired session.");
    }

    const { data: admin, error: adminError } =
      await supabase
        .from("admin_users")
        .select("user_id")
        .eq("user_id", data.user.id)
        .maybeSingle();

    if (adminError) throw adminError;

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
    console.error("AUTH ERROR:", error);
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

/* SERVER STATUS */

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
        email: email ? String(email).trim() : null,
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

      const { data: customer, error: customerError } =
        await supabase
          .from("customers")
          .select("id,phone,status")
          .eq("id", customer_id)
          .maybeSingle();

      if (customerError) throw customerError;

      if (!customer) {
        return fail(res, 404, "Customer not found.");
      }

      if (customer.phone.trim() !== String(phone).trim()) {
        return fail(res, 400, "Registered mobile number does not match.");
      }

      if (customer.status === "approved") {
        return fail(res, 409, "This customer is already approved.");
      }

      const { data: duplicate, error: duplicateError } =
        await supabase
          .from("payments")
          .select("id")
          .ilike("utr", cleanUtr)
          .limit(1)
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
        message: "Payment submitted. Waiting for verification."
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

/* ADMIN SESSION CHECK */

app.get(
  "/api/admin/me",
  authenticate,
  adminOnly,
  async (req, res) => {
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
  }
);

/* ADMIN DASHBOARD DATA */

app.get(
  "/api/admin/customers",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const [customerResult, paymentResult, keyResult] =
        await Promise.all([
          supabase
            .from("customers")
            .select("id,full_name,phone,email,plan,amount,status,created_at")
            .order("created_at", { ascending: false }),

          supabase
            .from("payments")
            .select("id,customer_id,utr,screenshot_path,status,created_at,verified_at")
            .order("created_at", { ascending: false }),

          supabase
            .from("api_keys")
            .select("id,customer_id,key_prefix,status,created_at")
            .order("created_at", { ascending: false })
        ]);

      if (customerResult.error) throw customerResult.error;
      if (paymentResult.error) throw paymentResult.error;
      if (keyResult.error) throw keyResult.error;

      return res.json({
        success: true,
        customers: customerResult.data || [],
        payments: paymentResult.data || [],
        api_keys: keyResult.data || []
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN PAYMENT LIST */

app.get(
  "/api/admin/payments",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("payments")
        .select("*")
        .order("created_at", { ascending: false });

      if (error) throw error;

      return res.json({
        success: true,
        payments: data || []
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* ADMIN API KEY LIST */

app.get(
  "/api/admin/api-keys",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("api_keys")
        .select("id,customer_id,key_prefix,status,created_at")
        .order("created_at", { ascending: false });

      if (error) throw error;

      return res.json({
        success: true,
        api_keys: data || []
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* PAYMENT SCREENSHOT */

async function sendPaymentImage(req, res) {
  try {
    const { data: payment, error } = await supabase
      .from("payments")
      .select("screenshot_path")
      .eq("id", req.params.id)
      .maybeSingle();

    if (error) throw error;

    if (!payment) {
      return fail(res, 404, "Payment not found.");
    }

    const { data, error: urlError } = await supabase.storage
      .from("payment-screenshots")
      .createSignedUrl(payment.screenshot_path, 120);

    if (urlError) throw urlError;

    return res.json({
      success: true,
      url: data.signedUrl
    });
  } catch (error) {
    return serverError(res, error);
  }
}

app.get(
  "/api/admin/payment-image/:id",
  authenticate,
  adminOnly,
  sendPaymentImage
);

app.get(
  "/api/admin/payments/:id/screenshot",
  authenticate,
  adminOnly,
  sendPaymentImage
);

/* APPROVE OR REJECT PAYMENT */

async function decidePayment(req, res, status) {
  try {
    const { data: payment, error: paymentError } = await supabase
      .from("payments")
      .select("id,customer_id,status")
      .eq("id", req.params.id)
      .maybeSingle();

    if (paymentError) throw paymentError;

    if (!payment) {
      return fail(res, 404, "Payment not found.");
    }

    const { error: updatePaymentError } = await supabase
      .from("payments")
      .update({
        status,
        verified_at: status === "approved"
          ? new Date().toISOString()
          : null
      })
      .eq("id", payment.id);

    if (updatePaymentError) throw updatePaymentError;

    const { error: updateCustomerError } = await supabase
      .from("customers")
      .update({ status })
      .eq("id", payment.customer_id);

    if (updateCustomerError) throw updateCustomerError;

    return res.json({
      success: true,
      message: `Payment ${status} successfully.`,
      customer_id: payment.customer_id
    });
  } catch (error) {
    return serverError(res, error);
  }
}

app.post(
  "/api/admin/payments/:id/decision",
  authenticate,
  adminOnly,
  async (req, res) => {
    const status = String((req.body || {}).status || "").toLowerCase();

    if (!["approved", "rejected"].includes(status)) {
      return fail(res, 400, "Status must be approved or rejected.");
    }

    return decidePayment(req, res, status);
  }
);

app.post(
  "/api/admin/approve/:id",
  authenticate,
  adminOnly,
  async (req, res) => decidePayment(req, res, "approved")
);

app.post(
  "/api/admin/reject/:id",
  authenticate,
  adminOnly,
  async (req, res) => decidePayment(req, res, "rejected")
);

/* ADMIN GENERATE API KEY AND CLIENT PASSWORD */

app.post(
  "/api/admin/customers/:id/api-key",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const customerId = req.params.id;

      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id,status,password_hash")
        .eq("id", customerId)
        .maybeSingle();

      if (customerError) throw customerError;

      if (!customer) {
        return fail(res, 404, "Customer not found.");
      }

      if (customer.status !== "approved") {
        return fail(res, 400, "Approve the customer's payment first.");
      }

      const { data: existing, error: existingError } = await supabase
        .from("api_keys")
        .select("id")
        .eq("customer_id", customerId)
        .eq("status", "active")
        .limit(1);

      if (existingError) throw existingError;

      if (existing && existing.length) {
        return fail(
          res,
          409,
          "This customer already has an active API key. Revoke it first."
        );
      }

      let temporaryPassword = null;

      if (!customer.password_hash) {
        temporaryPassword = crypto.randomBytes(12).toString("base64url");

        const passwordHash = await bcrypt.hash(temporaryPassword, 12);

        const { error: passwordError } = await supabase
          .from("customers")
          .update({ password_hash: passwordHash })
          .eq("id", customerId);

        if (passwordError) throw passwordError;
      }

      const rawKey = generateApiKey();

      const { data: savedKey, error: keyError } = await supabase
        .from("api_keys")
        .insert({
          customer_id: customerId,
          key_hash: hashApiKey(rawKey),
          key_prefix: rawKey.slice(0, 15),
          status: "active"
        })
        .select("id,customer_id,key_prefix,status,created_at")
        .single();

      if (keyError) throw keyError;

      return res.json({
        success: true,
        message: "API key generated successfully.",
        api_key: rawKey,
        temporary_password: temporaryPassword,
        key: savedKey,
        note: "Save the API key and password securely. They cannot be displayed again."
      });
    } catch (error) {
      return serverError(res, error);
    }
  }
);

/* CHANGE API KEY STATUS */

app.patch(
  "/api/admin/api-keys/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const status = String((req.body || {}).status || "").toLowerCase();

      if (!["active", "inactive", "revoked"].includes(status)) {
        return fail(res, 400, "Invalid API key status.");
      }

      const { data, error } = await supabase
        .from("api_keys")
        .update({ status })
        .eq("id", req.params.id)
        .select("id,status")
        .maybeSingle();

      if (error) throw error;

      if (!data) {
        return fail(res, 404, "API key not found.");
      }

      return res.json({
        success: true,
        message: "API key status updated.",
        key: data
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
      .select("id,full_name,phone,email,plan,status,password_hash")
      .eq("id", customer_id)
      .maybeSingle();

    if (error) throw error;

    if (!customer || !customer.password_hash) {
      return fail(res, 401, "Invalid Customer ID or password.");
    }

    const passwordOk = await bcrypt.compare(
      String(password),
      customer.password_hash
    );

    if (!passwordOk) {
      return fail(res, 401, "Invalid Customer ID or password.");
    }

    if (customer.status !== "approved") {
      return fail(res, 403, "Your payment is not approved yet.");
    }

    return res.json({
      success: true,
      token: createToken(customer.id, "client"),
      customer: {
        id: customer.id,
        full_name: customer.full_name,
        phone: customer.phone,
        email: customer.email,
        plan: customer.plan,
        status: customer.status
      }
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
      const { data: customer, error } = await supabase
        .from("customers")
        .select("id,full_name,phone,email,plan,amount,status,created_at")
        .eq("id", req.user.id)
        .maybeSingle();

      if (err
