
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

app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true
}));

app.use(express.json({ limit: "100kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    cb(null, [
      "image/jpeg",
      "image/png",
      "image/webp"
    ].includes(file.mimetype));
  }
});

function fail(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function serverError(res, error) {
  console.error(error);
  return fail(res, 500, "Server error. Check Render logs.");
}

function createToken(id, role) {
  return jwt.sign(
    { id, role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) return fail(res, 401, "Please login first.");

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return fail(res, 401, "Session expired. Please login again.");
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return fail(res, 403, "Admin access required.");
  }
  next();
}

function clientOnly(req, res, next) {
  if (req.user.role !== "client") {
    return fail(res, 403, "Client access required.");
  }
  next();
}

async function getActiveClient(id) {
  const { data, error } = await supabase
    .from("customers")
    .select("id,status")
    .eq("id", id)
    .single();

  if (error || !data || data.status !== "approved") return null;
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

    const cleanPhone = String(phone).trim();

    if (!/^[0-9+\-\s]{10,15}$/.test(cleanPhone)) {
      return fail(res, 400, "Invalid mobile number.");
    }

    const { data, error } = await supabase
      .from("customers")
      .insert({
        full_name: String(full_name).trim(),
        phone: cleanPhone,
        email: email ? String(email).trim() : null,
        plan,
        amount: prices[plan],
        status: "pending"
      })
      .select("id")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      customer: { id: data.id },
      message: "Registration successful."
    });
  } catch (error) {
    serverError(res, error);
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
          .single();

      if (customerError || !customer) {
        return fail(res, 404, "Customer not found.");
      }

      if (customer.phone.trim() !== String(phone).trim()) {
        return fail(res, 400, "Registered mobile number does not match.");
      }

      const { data: duplicate } = await supabase
        .from("payments")
        .select("id")
        .ilike("utr", cleanUtr)
        .maybeSingle();

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

      res.json({
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
      serverError(res, error);
    }
  }
);

/* ADMIN LOGIN: ADMIN MUST EXIST IN SUPABASE AUTH
   AND admin_users.user_id MUST CONTAIN THEIR AUTH USER ID. */
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return fail(res, 400, "Email and password are required.");
    }

    const { data, error } = await authClient.auth
      .signInWithPassword({
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

    if (adminError || !admin) {
      return fail(res, 403, "This user is not an authorized admin.");
    }

    res.json({
      success: true,
      token: createToken(data.user.id, "admin")
    });
  } catch (error) {
    serverError(res, error);
  }
});

/* ADMIN: CUSTOMER LIST */
app.get("/api/admin/customers", authenticate, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("customers")
      .select("id,full_name,phone,email,plan,amount,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, customers: data });
  } catch (error) {
    serverError(res, error);
  }
});

/* ADMIN: PAYMENT LIST */
app.get("/api/admin/payments", authenticate, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("payments")
      .select("id,customer_id,utr,screenshot_path,status,created_at,verified_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, payments: data });
  } catch (error) {
    serverError(res, error);
  }
});

/* ADMIN: SECURE SCREENSHOT URL */
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
        .single();

      if (error || !payment) return fail(res, 404, "Payment not found.");

      const { data, error: urlError } = await supabase.storage
        .from("payment-screenshots")
        .createSignedUrl(payment.screenshot_path, 60);

      if (urlError) throw urlError;

      res.json({ success: true, url: data.signedUrl });
    } catch (error) {
      serverError(res, error);
    }
  }
);

/* ADMIN: APPROVE PAYMENT
   First approval creates a temporary client password.
   Admin must securely give it to the client. */
app.post(
  "/api/admin/approve/:id",
  authenticate,
  adminOnly,
  async (req, res) => {
    try {
      const { data: payment, error: paymentError } =
        await supabase
          .from("payments")
          .select("id,customer_id,status")
          .eq("id", req.params.id)
          .single();

      if (paymentError || !payment) {
        return fail(res, 404, "Payment not found.");
      }

      if (payment.status === "approved") {
        return fail(res, 409, "Payment is already approved.");
      }

      const { data: customer, error: customerError } =
        await supabase
          .from("customers")
          .select("id,password_hash")
          .eq("id", payment.customer_id)
          .single();

      if (customerError || !customer) {
        return fail(res, 404, "Customer not found.");
      }

      const { data: activeKeys, error: keyReadError } =
        await supabase
          .from("api_keys")
          .select("id")
          .eq("customer_id", customer.id)
          .eq("status", "active");

      if (keyReadError) throw keyReadError;

      let temporaryPassword = null;
      let rawKey = null;

      if (!customer.password_hash) {
        temporaryPassword = crypto.randomBytes(9).toString("base64url");

        const passwordHash = await bcrypt.hash(
          temporaryPassword,
          12
        );

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

      res.json({
        success: true,
        message: "Client approved successfully.",
        customer_id: customer.id,
        temporary_password: temporaryPassword,
        api_key: rawKey,
        note: "Save credentials securely. They are not shown again."
      });
    } catch (error) {
      serverError(res, error);
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

      res.json({
        success: true,
        message: "Payment rejected."
      });
    } catch (error) {
      serverError(res, error);
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
      .single();

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

    if (!valid) return fail(res, 401, "Incorrect password.");

    res.json({
      success: true,
      token: createToken(customer.id, "client")
    });
  } catch (error) {
    serverError(res, error);
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

      if (!customer) return fail(res, 403, "Client access is disabled.");

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

      res.json({
        success: true,
        customer: profile,
        api_keys: keys
      });
    } catch (error) {
      serverError(res, error);
    }
  }
);

/* CLIENT: REVOKE OWN KEY */
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
        .single();

      if (findError || !key) return fail(res, 404, "Active key not found.");

      const { error } = await supabase
        .from("api_keys")
        .update({ status: "revoked" })
        .eq("id", key.id);

      if (error) throw error;

      res.json({
        success: true,
        message: "API key revoked."
      });
    } catch (error) {
      serverError(res, error);
    }
  }
);

/* API KEY AUTHENTICATION CHECK.
   This validates keys only; it does not send WhatsApp messages. */
app.post("/api/key/validate", async (req, res) => {
  try {
    const rawKey = String(req.body.api_key || "");

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

    if (!customer) return fail(res, 403, "Client is not active.");

    res.json({
      success: true,
      message: "API key is valid.",
      customer_id: key.customer_id
    });
  } catch (error) {
    serverError(res, error);
  }
});

app.listen(PORT, () => {
  console.log("ADS GROWTH server running on port " + PORT);
});
                                              
