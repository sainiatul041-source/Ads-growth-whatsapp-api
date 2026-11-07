
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

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
  throw new Error("Supabase environment variables are missing");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

// Security and basic settings
app.use(helmet());

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "1mb" }));

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const upload = multer({
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

function safeError(res, error, message = "Request failed") {
  console.error(message, error.message || error);
  return res.status(500).json({
    success: false,
    message
  });
}

// Check admin's Supabase login token and admin permission
async function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Login required"
      });
    }

    const { data: userData, error: authError } =
      await supabase.auth.getUser(token);

    if (authError || !userData.user) {
      return res.status(401).json({
        success: false,
        message: "Invalid login"
      });
    }

    const { data: admin, error } = await supabase
      .from("admin_users")
      .select("user_id")
      .eq("user_id", userData.user.id)
      .maybeSingle();

    if (error) throw error;

    if (!admin) {
      return res.status(403).json({
        success: false,
        message: "Admin permission required"
      });
    }

    req.admin = userData.user;
    next();

  } catch (error) {
    return safeError(res, error, "Admin verification failed");
  }
}

// Health check
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "ADS GROWTH API Server is running",
    version: "2.0.0"
  });
});

// CUSTOMER REGISTRATION
app.post("/api/register", registrationLimiter, async (req, res) => {
  try {
    const { full_name, phone, email, plan, amount } = req.body;

    const validPlans = {
      Starter: 4999,
      Business: 7999,
      Enterprise: 9999
    };

    if (
      typeof full_name !== "string" ||
      full_name.trim().length < 2 ||
      full_name.trim().length > 100 ||
      typeof phone !== "string" ||
      !/^[0-9+\-\s]{10,15}$/.test(phone.trim()) ||
      !validPlans[plan] ||
      validPlans[plan] !== Number(amount)
    ) {
      return res.status(400).json({
        success: false,
        message: "Please enter valid registration details"
      });
    }

    const { data, error } = await supabase
      .from("customers")
      .insert([{
        full_name: full_name.trim(),
        phone: phone.trim(),
        email: typeof email === "string" ? email.trim() || null : null,
        plan,
        amount: Number(amount)
      }])
      .select("id,full_name,phone,plan,amount,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Registration successful",
      customer: data
    });

  } catch (error) {
    safeError(res, error, "Registration failed");
  }
});

// CUSTOMER PAYMENT SUBMISSION
// Customer ID and registered phone are required.
// Screenshot is stored in the private Supabase bucket.
app.post(
  "/api/payment-submit",
  paymentLimiter,
  upload.single("screenshot"),
  async (req, res) => {
    let uploadedPath = null;

    try {
      const { customer_id, phone, utr } = req.body;

      if (
        !customer_id ||
        typeof phone !== "string" ||
        typeof utr !== "string" ||
        !/^[A-Za-z0-9]{6,30}$/.test(utr.trim()) ||
        !req.file
      ) {
        return res.status(400).json({
          success: false,
          message: "Customer ID, registered phone, valid UTR and screenshot are required"
        });
      }

      const { data: customer, error: customerError } = await supabase
        .from("customers")
        .select("id,phone,status")
        .eq("id", customer_id)
        .eq("phone", phone.trim())
        .maybeSingle();

      if (customerError) throw customerError;

      if (!customer) {
        return res.status(404).json({
          success: false,
          message: "Customer not found. Check your ID and phone number."
        });
      }

      if (customer.status === "approved") {
        return res.status(400).json({
          success: false,
          message: "This customer is already approved"
        });
      }

      const { data: existing, error: duplicateError } = await supabase
        .from("payments")
        .select("id")
        .ilike("utr", utr.trim())
        .limit(1);

      if (duplicateError) throw duplicateError;

      if (existing && existing.length > 0) {
        return res.status(409).json({
          success: false,
          message: "This UTR has already been submitted"
        });
      }

      const extension = {
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp"
      }[req.file.mimetype];

      if (!extension) {
        return res.status(400).json({
          success: false,
          message: "Unsupported screenshot format"
        });
      }

      const filename =
        customer.id + "/" +
        Date.now() + "-" +
        crypto.randomBytes(8).toString("hex") +
        "." + extension;

      const { error: uploadError } = await supabase.storage
        .from(BUCKET)
        .upload(filename, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;

      uploadedPath = filename;

      const { data: payment, error: paymentError } = await supabase
        .from("payments")
        .insert([{
          customer_id: customer.id,
          utr: utr.trim(),
          screenshot_path: filename,
          status: "pending"
        }])
        .select("id,customer_id,utr,status,created_at")
        .single();

      if (paymentError) throw paymentError;

      res.status(201).json({
        success: true,
        message: "Payment details submitted for manual verification",
        payment
      });

    } catch (error) {
      if (uploadedPath) {
        await supabase.storage.from(BUCKET).remove([uploadedPath]);
      }
      safeError(res, error, "Payment submission failed");
    }
  }
);

// ADMIN: CHECK LOGIN AND PERMISSION
app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({
    success: true,
    admin: {
      id: req.admin.id,
      email: req.admin.email
    }
  });
});

// ADMIN: VIEW ALL CUSTOMERS AND PAYMENTS
app.get("/api/admin/customers", requireAdmin, async (req, res) => {
  try {
    const { data: customers, error: customerError } = await supabase
      .from("customers")
      .select("*")
      .order("created_at", { ascending: false });

    if (customerError) throw customerError;

    const { data: payments, error: paymentError } = await supabase
      .from("payments")
      .select("id,customer_id,utr,status,created_at,verified_at,screenshot_path")
      .order("created_at", { ascending: false });

    if (paymentError) throw paymentError;

    const { data: keys, error: keyError } = await supabase
      .from("api_keys")
      .select("id,customer_id,status,created_at");

    if (keyError) throw keyError;

    const result = customers.map(customer => ({
      ...customer,
      payments: payments.filter(p => p.customer_id === customer.id),
      api_keys: keys.filter(k => k.customer_id === customer.id)
    }));

    res.json({
      success: true,
      total: result.length,
      customers: result
    });

  } catch (error) {
    safeError(res, error, "Could not load customers");
  }
});

// ADMIN: VIEW A PRIVATE PAYMENT SCREENSHOT
app.get("/api/admin/payments/:id/screenshot", requireAdmin, async (req, res) => {
  try {
    const { data: payment, error } = await supabase
      .from("payments")
      .select("screenshot_path")
      .eq("id", req.params.id)
      .single();

    if (error) throw error;

    const { data, error: signedError } = await supabase.storage
      .from(BUCKET)
      .createSignedUrl(payment.screenshot_path, 300);

    if (signedError) throw signedError;

    res.json({
      success: true,
      url: data.signedUrl,
      expires_in_seconds: 300
    });

  } catch (error) {
    safeError(res, error, "Could not open screenshot");
  }
});

// ADMIN: APPROVE OR REJECT PAYMENT
app.post("/api/admin/payments/:id/decision", requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be approved or rejected"
      });
    }

    const { data: payment, error: findError } = await supabase
      .from("payments")
      .select("id,customer_id")
      .eq("id", req.params.id)
      .single();

    if (findError) throw findError;

    const { error: paymentError } = await supabase
      .from("payments")
      .update({
        status,
        verified_at: new Date().toISOString()
      })
      .eq("id", payment.id);

    if (paymentError) throw paymentError;

    const { error: customerError } = await supabase
      .from("customers")
      .update({ status })
      .eq("id", payment.customer_id);

    if (customerError) throw customerError;

    res.json({
      success: true,
      message: "Payment " + status,
      customer_id: payment.customer_id
    });

  } catch (error) {
    safeError(res, error, "Payment decision failed");
  }
});

// ADMIN: CREATE AND ASSIGN A NEW API KEY
// The actual key is returned only once. Only its hash is stored.
app.post("/api/admin/customers/:id/api-key", requireAdmin, async (req, res) => {
  try {
    const { data: customer, error: customerError } = await supabase
      .from("customers")
      .select("id,status")
      .eq("id", req.params.id)
      .single();

    if (customerError) throw customerError;

    if (customer.status !== "approved") {
      return res.status(400).json({
        success: false,
        message: "Approve the customer's payment before issuing an API key"
      });
    }

    const plainKey =
      "ag_live_" + crypto.randomBytes(32).toString("hex");

    const keyHash = crypto
      .createHash("sha256")
      .update(plainKey)
      .digest("hex");

    await supabase
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("customer_id", customer.id)
      .eq("status", "active");

    const { data: keyRecord, error } = await supabase
      .from("api_keys")
      .insert([{
        customer_id: customer.id,
        key_hash: keyHash,
        status: "active"
      }])
      .select("id,customer_id,status,created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "API key created. Save it now; it cannot be viewed again.",
      api_key: plainKey,
      record: keyRecord
    });

  } catch (error) {
    safeError(res, error, "API key creation failed");
  }
});

// ADMIN: ACTIVATE, DEACTIVATE OR REVOKE A KEY
app.patch("/api/admin/api-keys/:id", requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["active", "inactive", "revoked"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid API key status"
      });
    }

    const { data, error } = await supabase
      .from("api_keys")
      .update({ status })
      .eq("id", req.params.id)
      .select("id,customer_id,status,created_at")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "API key status updated",
      api_key: data
    });

  } catch (error) {
    safeError(res, error, "Could not update API key");
  }
});

// Not found
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found"
  });
});

// General error handler
app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message: "Screenshot must be 5 MB or smaller"
    });
  }

  res.status(500).json({
    success: false,
    message: "Server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("ADS GROWTH API server running on port " + PORT);
});
  
