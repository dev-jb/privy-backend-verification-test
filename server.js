const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Import verification functions
const { PrivyJWKSVerifier } = require('./jwks-verifier');
const { PrivyClient } = require('@privy-io/node');

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize JWKS verifier
const jwksVerifier = new PrivyJWKSVerifier(process.env.PRIVY_APP_ID);

// Initialize Privy SDK client
const privy = new PrivyClient({
  appId: process.env.PRIVY_APP_ID,
  apiKey: process.env.PRIVY_APP_SECRET,
  jwtVerificationKey: process.env.PRIVY_JWT_VERIFICATION_KEY,
});

// Privy SDK middleware for simple verification using JWT verification key
const verifyPrivyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'No valid authorization header',
        code: 'NO_AUTH_HEADER',
      });
    }

    const accessToken = authHeader.replace('Bearer ', '');
    const verifiedClaims = await privy
      .utils()
      .auth()
      .verifyAuthToken(accessToken);

    // Attach user data to request object
    req.user = {
      userId: verifiedClaims.userId,
      appId: verifiedClaims.appId,
      sessionId: verifiedClaims.sessionId,
      issuedAt: verifiedClaims.issuedAt,
      expiration: verifiedClaims.expiration,
    };

    next();
  } catch (error) {
    console.error('Privy SDK verification failed:', error);
    res.status(401).json({
      error: 'Token verification failed',
      code: 'VERIFICATION_FAILED',
      details: error.message,
    });
  }
};

// Middleware
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  })
);
app.use(express.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Backend server is running',
    timestamp: new Date().toISOString(),
  });
});

// Simple protected endpoint using Privy SDK middleware
app.get('/api/protected-sdk', verifyPrivyToken, (req, res) => {
  res.json({
    message: 'Access granted via Privy SDK verification!',
    user: req.user,
    verificationMethod: 'Privy SDK',
    timestamp: new Date().toISOString(),
  });
});

// JWKS-based protected endpoint
app.get('/api/protected-jwks', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'No valid authorization header',
        code: 'NO_AUTH_HEADER',
      });
    }

    const accessToken = authHeader.replace('Bearer ', '');
    const user = await jwksVerifier.verifyToken(accessToken);

    res.json({
      message: 'Access granted via JWKS verification!',
      user: user,
      verificationMethod: 'JWKS',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('JWKS verification failed:', error);
    res.status(401).json({
      error: 'Token verification failed',
      code: 'VERIFICATION_FAILED',
      details: error.message,
    });
  }
});

// User profile endpoint using Privy SDK middleware
app.get('/api/user/profile', verifyPrivyToken, (req, res) => {
  res.json({
    message: 'User profile data',
    user: {
      id: req.user.userId,
      sessionId: req.user.sessionId,
      appId: req.user.appId,
      tokenIssuedAt: new Date(req.user.issuedAt * 1000).toISOString(),
      tokenExpiresAt: new Date(req.user.expiration * 1000).toISOString(),
    },
    verificationMethod: 'Privy SDK',
    timestamp: new Date().toISOString(),
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server error:', error);

  if (error.message.includes('jwt expired')) {
    return res.status(401).json({
      error: 'Token expired',
      code: 'TOKEN_EXPIRED',
    });
  }

  if (error.message.includes('invalid signature')) {
    return res.status(401).json({
      error: 'Invalid token signature',
      code: 'INVALID_TOKEN',
    });
  }

  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.originalUrl,
  });
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);

  if (!process.env.PRIVY_APP_ID || !process.env.PRIVY_APP_SECRET) {
    console.log('Warning: Missing required environment variables!');
    console.log('Please check your .env file.');
  }
});
