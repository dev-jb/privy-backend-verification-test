# Privy Backend Auth verification Test

## Quick Start

### 1. Install Dependencies

```bash
cd backend
npm install
```

### 2. Set Up Environment Variables

Copy the example environment file and fill in your Privy credentials:

```bash
cp env.example .env
```

Edit `.env` with your actual values:

```env
PRIVY_APP_ID=xxxxxxxxxxxxxxx
PRIVY_APP_SECRET=xxxxxxxxxxxxxxx
PRIVY_JWT_VERIFICATION_KEY=xxxxxxxxxxxxxxx
PORT=3001
FRONTEND_URL=http://localhost:3000
```

### 3. Get Your Privy Credentials

1. Go to [Privy Dashboard](https://dashboard.privy.io/)
2. Select your app
3. Go to **Configuration > App settings**
4. Get necessary keys

### 4. Run the Server

```bash
npm run start
```

The server will start on `http://localhost:3001`

## API Endpoints

### Public Endpoints

- `GET /api/health` - Health check

### Protected Endpoints

- `GET /api/protected-sdk` - Protected using Privy SDK middleware (For using static key)
- `GET /api/protected-jwks` - Protected using jwks verification (For using key rotation)

## Testing the Backend

### 1. Test Health Check

```bash
curl http://localhost:3001/api/health
```

### 2. Test Protected SDK (with token)

```bash
# Replace YOUR_ACCESS_TOKEN with actual token from frontend
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:3001/api/protected-sdk
```

### 3. Test Protected JWKS Endpoint (with token)

```bash
# Replace YOUR_ACCESS_TOKEN with actual token from frontend
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:3001/api/protected-jwks
```
