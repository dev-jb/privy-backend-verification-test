const jose = require('jose');

/**
 * JWKS-based JWT verifier for Privy tokens
 * Fetches keys dynamically from Privy's JWKS endpoint
 */
class PrivyJWKSVerifier {
  constructor(appId) {
    this.appId = appId;
    this.jwksUrl = `https://auth.privy.io/api/v1/apps/${appId}/jwks.json`;
    this.keyCache = new Map();
    this.cacheExpiry = 0;
    this.cacheDuration = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Fetch JWKS from Privy's endpoint
   */
  async fetchJWKS() {
    try {
      const response = await fetch(this.jwksUrl);
      if (!response.ok) {
        throw new Error(
          `Failed to fetch JWKS: ${response.status} ${response.statusText}`
        );
      }
      const jwks = await response.json();
      return jwks;
    } catch (error) {
      console.error('Error fetching JWKS:', error);
      throw error;
    }
  }

  /**
   * Get verification key for a specific key ID
   */
  async getVerificationKey(kid) {
    // Check cache first
    if (this.keyCache.has(kid) && Date.now() < this.cacheExpiry) {
      return this.keyCache.get(kid);
    }

    // Fetch fresh JWKS
    const jwks = await this.fetchJWKS();

    // Find the key with matching kid
    const key = jwks.keys.find((k) => k.kid === kid);
    if (!key) {
      throw new Error(`Key with kid '${kid}' not found in JWKS`);
    }

    // Convert JWK to verification key
    const verificationKey = await jose.importJWK(key, 'ES256');

    // Cache the key
    this.keyCache.set(kid, verificationKey);
    this.cacheExpiry = Date.now() + this.cacheDuration;

    return verificationKey;
  }

  /**
   * Verify a Privy JWT token
   */
  async verifyToken(accessToken) {
    try {
      // Decode header to get key ID
      const [headerB64] = accessToken.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

      if (!header.kid) {
        throw new Error('Token header missing key ID (kid)');
      }

      // Get the verification key
      const verificationKey = await this.getVerificationKey(header.kid);

      // Verify the JWT
      const { payload } = await jose.jwtVerify(accessToken, verificationKey, {
        issuer: 'privy.io',
        audience: this.appId,
      });

      return {
        userId: payload.sub,
        appId: payload.aud,
        sessionId: payload.sid,
        issuedAt: payload.iat,
        expiration: payload.exp,
        keyId: header.kid,
      };
    } catch (error) {
      console.error('JWT verification failed:', error);
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Get all available key IDs (for debugging)
   */
  async getAvailableKeyIds() {
    const jwks = await this.fetchJWKS();
    return jwks.keys.map((key) => key.kid);
  }
}

module.exports = { PrivyJWKSVerifier };
