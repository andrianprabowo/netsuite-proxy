const express = require("express");
const fetch = require("node-fetch");
const CryptoJS = require("crypto-js");
const cors = require("cors");

const app = express();
// const port = process.env.PORT;
const port = process.env.PORT || 8080;

// ✅ CORS Middleware
app.use(
  cors({
    origin: "*", // Ganti dengan domain spesifik jika sudah produksi
    methods: "GET,POST",
    allowedHeaders: "Content-Type,Authorization,X-PP-Token", // <- tambahkan X-PP-Token
  })
);

// ✅ Middleware parsing JSON untuk POST request
app.use(express.json());

// ✅ Health check endpoint
app.get("/", (req, res) => {
  res.send("✅ Proxy is running!");
});

// ✅ NetSuite OAuth credentials
const url =
  "https://td2889608.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=285&deploy=1";
const realm = "TD2889608";
const consumerKey =
  "228ed224b165f917e366351bcf8bd23fdecc0416c841a1bb0f737cbb81766afa";
const consumerSecret =
  "03e3802643afa049388980fcd318c094d0a70a8006a6f7e6173ec47129e5652a";
const accessToken =
  "7153bad1a66c0a28ecf57f8114e445e1ec9aca142015f6e2c0a674de431d2666";
const tokenSecret =
  "32385a5c907d51bedd82ae346403e62355a1c4b4d8be5f902d5c709d7d48fde9";

// ✅ OAuth utils
function getTimestamp() {
  return Math.floor(Date.now() / 1000);
}

function getNonce(length = 11) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function percentEncode(str) {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function createSignatureBaseString(method, baseUrl, params) {
  const sortedKeys = Object.keys(params).sort();
  const paramString = sortedKeys
    .map((key) => `${percentEncode(key)}=${percentEncode(params[key])}`)
    .join("&");
  return [
    method.toUpperCase(),
    percentEncode(baseUrl),
    percentEncode(paramString),
  ].join("&");
}

function createSignature(baseString, consumerSecret, tokenSecret) {
  const key = percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret);
  const hash = CryptoJS.HmacSHA256(baseString, key);
  return hash.toString(CryptoJS.enc.Base64);
}

function buildAuthHeader(params, realm) {
  const headerParams = [`realm="${realm}"`].concat(
    Object.keys(params).map(
      (key) => `${percentEncode(key)}="${percentEncode(params[key])}"`
    )
  );
  return "OAuth " + headerParams.join(", ");
}

// ✅ GET route proxy (existing) — forward X-PP-Token
app.get("/proxy/users", async (req, res) => {
  console.log("🔥 /proxy/users HIT");

  const httpMethod = "GET";

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: accessToken,
    oauth_nonce: getNonce(),
    oauth_timestamp: getTimestamp(),
    oauth_signature_method: "HMAC-SHA256",
    oauth_version: "1.0",
  };

  const urlObj = new URL(url);
  const queryParams = {};
  urlObj.searchParams.forEach((value, key) => {
    queryParams[key] = value;
  });

  const allParams = { ...queryParams, ...oauthParams };
  const baseUrl = url.split("?")[0];
  const baseString = createSignatureBaseString(httpMethod, baseUrl, allParams);
  const signature = createSignature(baseString, consumerSecret, tokenSecret);
  oauthParams.oauth_signature = signature;
  const authHeader = buildAuthHeader(oauthParams, realm);

  console.log("🔐 Authorization header:", authHeader);

  // ambil token dari header/query client
  const clientToken = req.header("x-pp-token") || req.query.token || "";

  try {
    const response = await fetch(url, {
      method: httpMethod,
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
        ...(clientToken ? { "X-PP-Token": clientToken } : {}), // ← forward token ke Restlet
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Response error:", response.status, errorText);
      return res.status(response.status).json({ error: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("❌ Proxy error:", err);
    res.status(500).json({ error: "Proxy call failed", detail: err.message });
  }
});

// ✅ POST proxy — forward X-PP-Token juga
app.post("/proxy", async (req, res) => {
  console.log("🔥 /proxy POST HIT");

  const httpMethod = "POST";
  const postData = req.body;

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: accessToken,
    oauth_nonce: getNonce(),
    oauth_timestamp: getTimestamp(),
    oauth_signature_method: "HMAC-SHA256",
    oauth_version: "1.0",
  };

  const urlObj = new URL(url);
  const queryParams = {};
  urlObj.searchParams.forEach((value, key) => {
    queryParams[key] = value;
  });

  const allParams = { ...queryParams, ...oauthParams };
  const baseUrl = url.split("?")[0];
  const baseString = createSignatureBaseString(httpMethod, baseUrl, allParams);
  const signature = createSignature(baseString, consumerSecret, tokenSecret);
  oauthParams.oauth_signature = signature;
  const authHeader = buildAuthHeader(oauthParams, realm);

  console.log("🔐 Authorization header:", authHeader);

  // token bisa datang dari header / body / query
  const clientToken =
    req.header("x-pp-token") || req.body?.token || req.query?.token || "";

  try {
    const response = await fetch(url, {
      method: httpMethod,
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
        ...(clientToken ? { "X-PP-Token": clientToken } : {}), // ← forward token ke Restlet
      },
      body: JSON.stringify(postData), // biarkan body seperti semula
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Response error:", response.status, errorText);
      return res.status(response.status).json({ error: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("❌ Proxy POST error:", err);
    res
      .status(500)
      .json({ error: "Proxy POST call failed", detail: err.message });
  }
});

// ✅ Start server
app.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Proxy server listening at http://0.0.0.0:${port}`);
});
