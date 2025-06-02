const express = require("express");
const fetch = require("node-fetch");
const CryptoJS = require("crypto-js");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json()); // untuk parsing JSON body POST
const port = 3001;

// OAuth Credentials
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

// GET /proxy/users (ambil data)
app.get("/proxy/users", async (req, res) => {
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

  try {
    const response = await fetch(url, {
      method: httpMethod,
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Proxy GET call failed", detail: err.message });
  }
});

// POST /proxy (kirim data)
app.post("/proxy", async (req, res) => {
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

  try {
    const response = await fetch(url, {
      method: httpMethod,
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(postData),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({ error: errorText });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    res
      .status(500)
      .json({ error: "Proxy POST call failed", detail: err.message });
  }
});

app.listen(port, () => {
  console.log(`Proxy server listening at http://localhost:${port}`);
});
