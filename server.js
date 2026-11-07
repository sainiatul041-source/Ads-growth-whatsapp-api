
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",")
    : true
}));
app.use(express.json({ limit: "1mb" }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "ADS GROWTH API Server is running"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const { full_name, phone, email, plan, amount } = req.body;

    if (!full_name || !phone || !plan || !amount) {
      return res.status(400).json({
        success: false,
        message: "Required details missing"
      });
    }

    const validPlans = {
      Starter: 4999,
      Business: 7999,
      Enterprise: 9999
    };

    if (validPlans[plan] !== Number(amount)) {
      return res.status(400).json({
        success: false,
        message: "Invalid plan or amount"
      });
    }

    const { data, error } = await supabase
      .from("customers")
      .insert([{
        full_name,
        phone,
        email: email || null,
        plan,
        amount: Number(amount)
      }])
      .select("id, full_name, status, created_at")
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      customer: data
    });

  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ADS GROWTH server running on ${PORT}`);
});
