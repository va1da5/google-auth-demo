import dotenv from "dotenv";

dotenv.config();

import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();

app.use(express.json()); // Middleware to parse JSON bodies

const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.VITE_GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_TOKEN_URI = process.env.GOOGLE_CLIENT_TOKEN_URI;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.VITE_GOOGLE_REDIRECT_URI;
const JWT_ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_TOKEN_SECRET;
const JWT_REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_TOKEN_SECRET;
const JWT_ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_ACCESS_TOKEN_EXPIRES_IN;
const JWT_REFRESH_TOKEN_EXPIRES_IN = process.env.JWT_REFRESH_TOKEN_EXPIRES_IN;

var corsOptions = {
  origin: new URL(GOOGLE_REDIRECT_URI).origin,
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
  credentials: true,
};

app.use(cors(corsOptions));

if (
  !GOOGLE_CLIENT_ID ||
  !GOOGLE_CLIENT_SECRET ||
  !GOOGLE_REDIRECT_URI ||
  !JWT_ACCESS_TOKEN_SECRET ||
  !JWT_REFRESH_TOKEN_SECRET
) {
  console.error("FATAL ERROR: Missing required environment variables.");
  process.exit(1);
}

function generateAccessToken(payload) {
  return jwt.sign(payload, JWT_ACCESS_TOKEN_SECRET, {
    expiresIn: JWT_ACCESS_TOKEN_EXPIRES_IN,
  });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, JWT_REFRESH_TOKEN_SECRET, {
    expiresIn: JWT_REFRESH_TOKEN_EXPIRES_IN,
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // No token

  jwt.verify(token, JWT_ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error("Access token verification error:", err.message);
      return res.sendStatus(403); // Invalid token (expired or tampered)
    }
    req.user = user; // Add decoded user payload to request
    next();
  });
}

app.get("/token", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).json({ error: "Authorization code is required." });
  }

  const tokenParams = new URLSearchParams({
    code: code,
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    redirect_uri: GOOGLE_REDIRECT_URI,
    grant_type: "authorization_code",
  });

  try {
    // 1. Exchange code for Google tokens (including id_token)
    console.log("Exchanging code for tokens with Google...");
    const googleResponse = await axios.post(
      GOOGLE_CLIENT_TOKEN_URI,
      tokenParams.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );

    const { id_token, access_token: google_access_token } = googleResponse.data;
    // console.log('Google Response Data:', googleResponse.data);

    if (!id_token) {
      console.error(
        "id_token not found in Google response:",
        googleResponse.data,
      );
      return res
        .status(500)
        .json({ error: "Failed to retrieve id_token from Google." });
    }

    // 2. Parse/decode the id_token to get user information
    // IMPORTANT: In a production app, you MUST verify the id_token signature
    // using Google's public keys to ensure its authenticity and integrity.
    // The `google-auth-library` package is recommended for this.
    // For this example, we'll just decode it to extract claims.
    const decodedIdToken = jwt.decode(id_token);
    // console.log("Decoded id_token:", decodedIdToken);

    if (!decodedIdToken || !decodedIdToken.sub) {
      console.error('Invalid id_token or missing "sub" claim.');
      return res
        .status(500)
        .json({ error: "Invalid id_token received from Google." });
    }

    // 3. Create your API's own session tokens (access and refresh)
    const tokenPayload = {
      userId: decodedIdToken.sub,
      email: decodedIdToken.email,
      name: decodedIdToken.name,
      picture: decodedIdToken.picture,
    };

    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

    // 4. Return your custom tokens to the frontend
    res.json({
      message: "Tokens generated successfully.",
      accessToken: accessToken,
      refreshToken: refreshToken,
      userInfo: tokenPayload,
    });
  } catch (error) {
    console.error(
      "Error during token exchange:",
      error.response ? error.response.data : error.message,
    );
    if (error.response && error.response.data && error.response.data.error) {
      // Google often returns specific error messages
      return res.status(error.response.status || 500).json({
        error: "Failed to exchange code with Google.",
        details:
          error.response.data.error_description || error.response.data.error,
      });
    }
    return res
      .status(500)
      .json({ error: "An internal server error occurred." });
  }
});

app.post("/token/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is required" });
  }

  try {
    const payload = jwt.verify(refreshToken, JWT_REFRESH_TOKEN_SECRET);
    delete payload.iat;
    delete payload.exp;
    res.json({ accessToken: generateAccessToken(payload) });
  } catch (err) {
    return res.status(401).json({ message: "Refresh token invalid" });
  }
});

app.get("/me", [cors(corsOptions), authenticateToken], (req, res) => {
  return res.json(req.user);
});

// Basic error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log(
    `Ensure your GOOGLE_CLIENT_ID is: ${GOOGLE_CLIENT_ID ? "SET" : "NOT SET"}`,
  );
  console.log(`Ensure your GOOGLE_REDIRECT_URI is: ${GOOGLE_REDIRECT_URI}`);
  console.log(`Ensure your JWT secrets are set.`);
});
