
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const multer = require("multer");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;
const BUCKET = "payment-screenshots";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SECRET_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 ||
        allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10
});

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5
});

app.use(generalLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG and WEBP images are allowed"));
    }
    cb(null, true);
  }
});

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function hashKey(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validPhone(phone) {
  return /^[0-9]{10,15}$/.test(String(phone || ""));
}

function validPlan(plan, amount) {
  const prices = {
    Starter: 4999,
    Business: 7999,
    Enterprise: 9999
  };
  return prices[plan] === Number(amount);
}

async function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return sendError(res, 401, "Admin login required");
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return sendError(res, 401, "Invalid or expired login");
    }

    const { data: admin, error: adminError } = await supabase
      .from("admin_users")
      .select("user_id")
      .eq("user_id", data.user.id)
      .maybeSingle();

    if (adminError || !admin) {
      return sendError(res, 403, "Admin access denied");
    }

    req.admin = data.user;
    next();
  } catch (error) {
    console.error("ADMIN AUTH ERROR:", error);
    return sendError(res, 500, "Admin authentication failed");
  }
}

async function requireClientApiKey(req, res, next) {
  try {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey || typeof apiKey !== "string") {
      return sendError(res, 401, "API key required");
    }

    const keyHash = hashKey(apiKey);

    const { data: key, error } = await supabase
      .from("api_keys")
      .select("id, customer_id, status")
      .eq("key_hash", keyHash)
      .eq("status", "active")
      .maybeSingle();

    if (error || !key) {
      return sendError(res, 401, "Invalid or inactive API key");
    }

    const { data: customer, error: customerError } = await supabase
      .from("customers")
      .select("id, status")
      .eq("id", key.customer_id)
      .eq("status", "approved")
      .maybeSingle();

    if (customerError || !customer) {
      return sendError(res, 403, "Customer account is not approved");
    }

    req.client = customer;
    req.apiKey = key;
    next();
  } catch (error) {
    console.error("API KEY ERROR:", error);
    return sendError(res, 500, "API key verification failed");
  }
}

// HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "ADS GROWTH API Server is running",
    version: "3.0.0"
  });
});

// CUSTOMER REGISTRATION
app.post("/api/register", registerLimiter, async (req, res) => {
  try {
    const { full_name, phone, email, plan, amount } = req.body;

    if (!full_name || !phone || !plan || !amount) {
      return sendError(res, 400, "Please fill all required fields");
    }

    if (!validPhone(phone)) {
      return sendError(res, 400, "Enter a valid phone number");
    }

    if (!validPlan(plan, amount)) {
      return sendError(res, 400, "Invalid plan or amount");
    }

    const { data, error } = await supabase
      .from("customers")
      .insert([{
        full_name: String(full_name).trim(),
        phone: String(phone),
        email: email ? String(email).trim() : null,
        plan,
        amount: Number(amount),
        status: "pending"
      }])
      .select("id, full_name, phone, email, plan, amount, status, created_at")
      .single();

    if (error) {
      console.error("REGISTER ERROR:", error);
      return sendError(res, 500, "Registration failed");
    }

    return res.status(201).json({
      success: true,
      message: "Registration successful",
      customer: data
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    return sendError(res, 500, "Server error during registration");
  }
});

// PAYMENT SCREENSHOT SUBMISSION
app.post(
  "/api/payment-submit",
  paymentLimiter,
  upload.single("screenshot"),
  async (req, res) => {
    let uploadedPath = null;

    try {
      const { customer_id, phone, utr } = req.body;

      if (!customer_id || !phone || !utr || !req.file) {
        return sendError(res, 400, "Customer ID, phone, UTR and screenshot required");
      }

      if (!validPhone(phone)) {
        return sendError(res, 400, "Invalid phone number");
      }

      const cleanUtr = String(utr).trim();

      if (cleanUtr.length < 6 || cleanUtr.length > 50) {
        return sendError(res, 400, "Invalid UTR");
      }

      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id, phone, status")
        .eq("id", customer_id)
        .eq("phone", phone)
        .maybeSingle();

      if (customerError || !customer) {
        return sendError(res, 404, "Customer not found");
      }

      if (customer.status === "approved") {
        return sendError(res, 409, "Customer is already approved");
      }

      const fileExt = req.file.mimetype === "image/png"
        ? "png"
        : req.file.mimetype === "image/webp"
          ? "webp"
          : "jpg";

      uploadedPath =
        `${customer.id}/${Date.now()}-${crypto.randomUUID()}.${fileExt}`;

      const { error: uploadError } = await supabase.storage
        .from(BUCKET)
        .upload(uploadedPath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) {
        console.error("SCREENSHOT UPLOAD ERROR:", uploadError);
        return sendError(res, 500, "Screenshot upload failed");
      }

      const { data: payment, error: paymentError } = await supabase
        .from("payments")
        .insert([{
          customer_id: customer.id,
          utr: cleanUtr,
          screenshot_path: uploadedPath,
          status: "pending"
        }])
        .select("id, customer_id, utr, status, created_at")
        .single();

      if (paymentError) {
        await supabase.storage.from(BUCKET).remove([uploadedPath]);

        console.error("PAYMENT INSERT ERROR:", paymentError);

        if (paymentError.code === "23505") {
          return sendError(res, 409, "This UTR has already been submitted");
        }

        return sendError(res, 500, "Payment submission failed");
      }

      return res.status(201).json({
        success: true,
        message: "Payment submitted for verification",
        payment
      });
    } catch (error) {
      if (uploadedPath) {
        await supabase.storage.from(BUCKET).remove([uploadedPath]);
      }

      console.error("PAYMENT ERROR:", error);
      return sendError(res, 500, "Payment submission failed");
    }
  }
);

// ADMIN: VERIFY LOGIN
app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    success: true,
    admin: {
      id: req.admin.id,
      email: req.admin.email
    }
  });
});

// ADMIN: GET CUSTOMERS, PAYMENTS AND API KEYS
app.get("/api/admin/customers", requireAdmin, async (req, res) => {
  try {
    const [customersResult, paymentsResult, keysResult] = await Promise.all([
      supabase
        .from("customers")
        .select("*")
        .order("created_at", { ascending: false }),

      supabase
        .from("payments")
        .select("*")
        .order("created_at", { ascending: false }),

      supabase
        .from("api_keys")
        .select("id, customer_id, status, created_at")
        .order("created_at", { ascending: false })
    ]);

    if (customersResult.error) throw customersResult.error;
    if (paymentsResult.error) throw paymentsResult.error;
    if (keysResult.error) throw keysResult.error;

    res.json({
      success: true,
      total: customersResult.data.length,
      customers: customersResult.data,
      payments: paymentsResult.data,
      api_keys: keysResult.data
    });
  } catch (error) {
    console.error("ADMIN CUSTOMERS ERROR:", error);
    return sendError(res, 500, "Could not load customers");
  }
});

// ADMIN: GET PRIVATE PAYMENT SCREENSHOT URL
app.get(
  "/api/admin/payments/:id/screenshot",
  requireAdmin,
  async (req, res) => {
    try {
      const { data: payment, error } = await supabase
        .from("payments")
        .select("screenshot_path")
        .eq("id", req.params.id)
        .single();

      if (error || !payment || !payment.screenshot_path) {
        return sendError(res, 404, "Screenshot not found");
      }

      const { data, error: signedError } = await supabase.storage
        .from(BUCKET)
        .createSignedUrl(payment.screenshot_path, 60 * 5);

      if (signedError || !data) {
        return sendError(res, 500, "Could not open screenshot");
      }

      res.json({
        success: true,
        url: data.signedUrl
      });
    } catch (error) {
      console.error("SCREENSHOT ERROR:", error);
      return sendError(res, 500, "Screenshot request failed");
    }
  }
);

// ADMIN: APPROVE OR REJECT PAYMENT
app.post(
  "/api/admin/payments/:id/decision",
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;

      if (!["approved", "rejected"].includes(status)) {
        return sendError(res, 400, "Status must be approved or rejected");
      }

      const { data: payment, error: paymentError } = await supabase
        .from("payments")
        .select("id, customer_id, status")
        .eq("id", req.params.id)
        .single();

      if (paymentError || !payment) {
        return sendError(res, 404, "Payment not found");
      }

      const now = new Date().toISOString();

      const { error: updatePaymentError } = await supabase
        .from("payments")
        .update({
          status,
          verified_at: now
        })
        .eq("id", payment.id);

      if (updatePaymentError) throw updatePaymentError;

      const { error: updateCustomerError } = await supabase
        .from("customers")
        .update({ status })
        .eq("id", payment.customer_id);

      if (updateCustomerError) throw updateCustomerError;

      res.json({
        success: true,
        message: `Payment ${status}`,
        status
      });
    } catch (error) {
      console.error("PAYMENT DECISION ERROR:", error);
      return sendError(res, 500, "Could not update payment");
    }
  }
);

// ADMIN: GENERATE API KEY FOR APPROVED CUSTOMER
app.post(
  "/api/admin/customers/:id/api-key",
  requireAdmin,
  async (req, res) => {
    try {
      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id, status")
        .eq("id", req.params.id)
        .single();

      if (customerError || !customer) {
        return sendError(res, 404, "Customer not found");
      }

      if (customer.status !== "approved") {
        return sendError(res, 403, "Approve customer before generating API key");
      }

      const plainKey =
        "ag_live_" + crypto.randomBytes(32).toString("hex");

      const { data: keyRecord, error: keyError } = await supabase
        .from("api_keys")
        .insert([{
          customer_id: customer.id,
          key_hash: hashKey(plainKey),
          status: "active"
        }])
        .select("id, customer_id, status, created_at")
        .single();

      if (keyError) throw keyError;

      res.status(201).json({
        success: true,
        message: "API key generated. Save it now; it will not be shown again.",
        api_key: plainKey,
        record: keyRecord
      });
    } catch (error) {
      console.error("API KEY GENERATION ERROR:", error);
      return sendError(res, 500, "Could not generate API key");
    }
  }
);

// ADMIN: ACTIVATE, DEACTIVATE OR REVOKE API KEY
app.patch(
  "/api/admin/api-keys/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;

      if (!["active", "inactive", "revoked"].includes(status)) {
        return sendError(res, 400, "Invalid API key status");
      }

      const { data, error } = await supabase
        .from("api_keys")
        .update({ status })
        .eq("id", req.params.id)
        .select("id, customer_id, status, created_at")
        .single();

      if (error || !data) {
        return sendError(res, 404, "API key not found");
      }

      res.json({
        success: true,
        api_key: data
      });
    } catch (error) {
      console.error("API KEY UPDATE ERROR:", error);
      return sendError(res, 500, "Could not update API key");
    }
  }
);

// CLIENT: CHECK API KEY
app.get("/api/client/me", requireClientApiKey, (req, res) => {
  res.json({
    success: true,
    message: "API key is working",
    customer_id: req.client.id
  });
});

// CLIENT: SEND WHATSAPP MESSAGE THROUGH OFFICIAL META CLOUD API
app.post("/api/whatsapp/send", requireClientApiKey, async (req, res) => {
  try {
    const {
      to,
      message
    } = req.body;

    if (!to || !/^[0-9]{8,15}$/.test(String(to))) {
      return sendError(res, 400, "Enter recipient number with country code");
    }

    if (!message || typeof message !== "string" ||
        message.length > 4096) {
      return sendError(res, 400, "Enter a message (maximum 4096 characters)");
    }

    const phoneNumberId = process.env.META_PHONE_NUMBER_ID;
    const accessToken = process.env.META_ACCESS_TOKEN;
    const graphVersion = process.env.META_GRAPH_VERSION;

    if (!phoneNumberId || !accessToken || !graphVersion) {
      return sendError(res, 503, "WhatsApp Meta API is not configured");
    }

    const response = await fetch(
      `https://graph.facebook.com/${graphVersion}/${phoneNumberId}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          recipient_type: "individual",
          to: String(to),
          type: "text",
          text: {
            preview_url: false,
            body: message
          }
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("META API ERROR:", result);
      return res.status(response.status).json({
        success: false,
        message: "Meta WhatsApp API rejected the request",
        error: result.error?.message || "WhatsApp message failed"
      });
    }

    res.json({
      success: true,
      message: "WhatsApp message submitted",
      result
    });
  } catch (error) {
    console.error("WHATSAPP SEND ERROR:", error);
    return sendError(res, 500, "WhatsApp message could not be sent");
  }
});

// MULTER AND GENERAL ERROR HANDLER
app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err.message);

  if (err instanceof multer.MulterError) {
    return sendError(res, 400, "Screenshot must be 5MB or smaller");
  }

  if (err.message === "Only JPG, PNG and WEBP images are allowed") {
    return sendError(res, 400, err.message);
  }

  if (err.message === "Origin not allowed") {
    return sendError(res, 403, "Website origin not allowed");
  }

  return sendError(res, 500, "Internal server error");
});

app.listen(PORT, () => {
  console.log(`ADS GROWTH API Server running on port ${PORT}`);
});
                      
