
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
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD",
  "JWT_SECRET"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true
}));
app.use(express.json({ limit: "100kb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
});
app.use("/api", limiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    cb(null, allowed.includes(file.mimetype));
  }
});

const prices = {
  Starter: 4999,
  Business: 7999,
  Enterprise: 9999
};

function makeToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Login required."
    });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Session expired. Login again."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required."
    });
  }
  next();
}

function apiError(res, error) {
  console.error(error);
  return res.status(500).json({
    success: false,
    message: "Server error. Check Render logs."
  });
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "ADS GROWTH API",
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
      amount,
      message
    } = req.body || {};

    if (
      !full_name ||
      !phone ||
      !prices[plan] ||
      Number(amount) !== prices[plan]
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid registration details."
      });
    }

    const { data, error } = await supabase
      .from("customers")
      .insert({
        full_name: String(full_name).trim(),
        phone: String(phone).trim(),
        email: email || null,
        plan,
        amount: prices[plan],
        message: message || null,
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
  } catch (e) {
    apiError(res, e);
  }
});

/* PAYMENT PROOF SUBMISSION */
app.post(
  "/api/payment-submit",
  upload.single("screenshot"),
  async (req, res) => {
    try {
      const { customer_id, phone, utr } = req.body || {};

      if (!customer_id || !phone || !utr || !req.file) {
        return res.status(400).json({
          success: false,
          message: "All payment fields are required."
        });
      }

      const { data: customer, error: customerError } =
        await supabase
          .from("customers")
          .select("id,phone")
          .eq("id", customer_id)
          .single();

      if (customerError || !customer) {
        return res.status(404).json({
          success: false,
          message: "Customer not found."
        });
      }

      if (customer.phone !== phone) {
        return res.status(400).json({
          success: false,
          message: "Registered phone does not match."
        });
      }

      const cleanUtr = String(utr).trim();

      if (!/^[A-Za-z0-9]{6,30}$/.test(cleanUtr)) {
        return res.status(400).json({
          success: false,
          message: "Invalid UTR."
        });
      }

      const { data: existing } = await supabase
        .from("payments")
        .select("id")
        .ilike("utr", cleanUtr)
        .maybeSingle();

      if (existing) {
        return res.status(409).json({
          success: false,
          message: "This UTR has already been submitted."
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
          message: "Invalid screenshot format."
        });
      }

      const filePath =
        `${crypto.randomUUID()}.${extension}`;

      const { error: uploadError } = await supabase.storage
        .from("payment-screenshots")
        .upload(filePath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;

      const { data: payment, error } = await supabase
        .from("payments")
        .insert({
          customer_id,
          phone,
          utr: cleanUtr,
          screenshot_path: filePath,
          status: "pending"
        })
        .select("id")
        .single();

      if (error) {
        await supabase.storage
          .from("payment-screenshots")
          .remove([filePath]);
        throw error;
      }

      res.json({
        success: true,
        payment: { id: payment.id },
        message: "Payment submitted for manual verification."
      });
    } catch (e) {
      apiError(res, e);
    }
  }
);

/* ADMIN LOGIN */
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body || {};

  const validEmail =
    String(email || "").toLowerCase() ===
    process.env.ADMIN_EMAIL.toLowerCase();

  const validPassword =
    String(password || "") === process.env.ADMIN_PASSWORD;

  if (!validEmail || !validPassword) {
    return res.status(401).json({
      success: false,
      message: "Invalid admin credentials."
    });
  }

  const token = makeToken({
    id: "admin",
    role: "admin"
  });

  res.json({
    success: true,
    token
  });
});

/* ADMIN: VIEW CUSTOMERS AND PAYMENTS */
app.get("/api/admin/customers", auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("customers")
      .select("id,full_name,phone,email,plan,amount,status,created_at")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, customers: data });
  } catch (e) {
    apiError(res, e);
  }
});

app.get("/api/admin/payments", auth, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("payments")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({ success: true, payments: data });
  } catch (e) {
    apiError(res, e);
  }
});

/* ADMIN: VIEW PAYMENT SCREENSHOT */
app.get(
  "/api/admin/payment-image/:id",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const { data: payment, error } = await supabase
        .from("payments")
        .select("screenshot_path")
        .eq("id", req.params.id)
        .single();

      if (error || !payment) {
        return res.status(404).json({
          success: false,
          message: "Payment not found."
        });
      }

      const { data, error: urlError } = await supabase.storage
        .from("payment-screenshots")
        .createSignedUrl(payment.screenshot_path, 60);

      if (urlError) throw urlError;

      res.json({
        success: true,
        url: data.signedUrl
      });
    } catch (e) {
      apiError(res, e);
    }
  }
);

/* ADMIN: APPROVE PAYMENT AND CREATE CLIENT ACCESS */
app.post(
  "/api/admin/approve/:id",
  auth,
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
        return res.status(404).json({
          success: false,
          message: "Payment not found."
        });
      }

      if (payment.status === "approved") {
        return res.status(409).json({
          success: false,
          message: "Payment already approved."
        });
      }

      const { error: updatePaymentError } = await supabase
        .from("payments")
        .update({
          status: "approved",
          verified_at: new Date().toISOString()
        })
        .eq("id", payment.id);

      if (updatePaymentError) throw updatePaymentError;

      const { error: updateCustomerError } = await supabase
        .from("customers")
        .update({ status: "approved" })
        .eq("id", payment.customer_id);

      if (updateCustomerError) throw updateCustomerError;

      let { data: client, error: clientError } = await supabase
        .from("clients")
        .select("id")
        .eq("customer_id", payment.customer_id)
        .maybeSingle();

      if (clientError) throw clientError;

      if (!client) {
        const temporaryPassword =
          crypto.randomBytes(18).toString("hex");

        const passwordHash =
          await bcrypt.hash(temporaryPassword, 12);

        const { data: newClient, error } = await supabase
          .from("clients")
          .insert({
            customer_id: payment.customer_id,
            password_hash: passwordHash,
            status: "active"
          })
          .select("id")
          .single();

        if (error) throw error;
        client = newClient;
      } else {
        const { error } = await supabase
          .from("clients")
          .update({ status: "active" })
          .eq("id", client.id);

        if (error) throw error;
      }

      const rawKey = "ag_live_" +
        crypto.randomBytes(32).toString("hex");

      const keyHash = crypto
        .createHash("sha256")
        .update(rawKey)
        .digest("hex");

      const { error: keyError } = await supabase
        .from("api_keys")
        .insert({
          client_id: client.id,
          key_hash: keyHash,
          key_prefix: rawKey.slice(0, 15),
          status: "active"
        });

      if (keyError) throw keyError;

      /*
       * Key is returned only once to admin.
       * Save it securely and deliver it to the client.
       */
      res.json({
        success: true,
        message: "Client approved and API key generated.",
        client_id: client.id,
        api_key: rawKey
      });
    } catch (e) {
      apiError(res, e);
    }
  }
);

/* ADMIN: REJECT PAYMENT */
app.post(
  "/api/admin/reject/:id",
  auth,
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
    } catch (e) {
      apiError(res, e);
    }
  }
);

/* CLIENT LOGIN */
app.post("/api/client/login", async (req, res) => {
  try {
    const { customer_id, password } = req.body || {};

    if (!customer_id || !password) {
      return res.status(400).json({
        success: false,
        message: "Customer ID and password are required."
      });
    }

    const { data: client, error } = await supabase
      .from("clients")
      .select("id,customer_id,password_hash,status")
      .eq("customer_id", customer_id)
      .single();

    if (error || !client || client.status !== "active") {
      return res.status(401).json({
        success: false,
        message: "Client not found or not approved."
      });
    }

    const valid = await bcrypt.compare(
      String(password),
      client.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Invalid login credentials."
      });
    }

    const token = makeToken({
      id: client.id,
      role: "client"
    });

    res.json({
      success: true,
      token
    });
  } catch (e) {
    apiError(res, e);
  }
});

/* CLIENT DASHBOARD */
app.get("/api/client/dashboard", auth, async (req, res) => {
  try {
    if (req.user.role !== "client") {
      return res.status(403).json({
        success: false,
        message: "Client access required."
      });
    }

    const { data: client, error } = await supabase
      .from("clients")
      .select("id,customer_id,status")
      .eq("id", req.user.id)
      .single();

    if (error || !client || client.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Client access disabled."
      });
    }

    const { data: customer, error: customerError } =
      await supabase
        .from("customers")
        .select("full_name,phone,email,plan,amount,status")
        .eq("id", client.customer_id)
        .single();

    if (customerError) throw customerError;

    const { data: keys, error: keyError } = await supabase
      .from("api_keys")
      .select("id,key_prefix,status,created_at")
      .eq("client_id", client.id)
      .eq("status", "active");

    if (keyError) throw keyError;

    res.json({
      success: true,
      customer,
      api_keys: keys
    });
  } catch (e) {
    apiError(res, e);
  }
});

/* CLIENT: REVOKE OWN KEY */
app.post("/api/client/revoke-key/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "client") {
      return res.status(403).json({
        success: false,
        message: "Client access required."
      });
    }

    const { data: key, error: findError } = await supabase
      .from("api_keys")
      .select("id")
      .eq("id", req.params.id)
      .eq("client_id", req.user.id)
      .single();

    if (findError || !key) {
      return res.status(404).json({
        success: false,
        message: "API key not found."
      });
    }

    const { error } = await supabase
      .from("api_keys")
      .update({ status: "revoked" })
      .eq("id", key.id);

    if (error) throw error;

    res.json({
      success: true,
      message: "API key revoked."
    });
  } catch (e) {
    apiError(res, e);
  }
});

app.listen(PORT, () => {
  console.log(`ADS GROWTH server running on port ${PORT}`);
});
               
