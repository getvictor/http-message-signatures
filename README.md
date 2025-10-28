# HTTP Message Signatures Demo

A comprehensive demonstration of **RFC 9421 (HTTP Message Signatures)** and **RFC 9530 (Digest Fields)** with full cryptographic signature verification using Ed25519 keys.

## Prerequisites

- **Node.js**: >=24.0.0 (uses stable Web Crypto API)
- **npm**: >=10.0.0

### Using nvm (Node Version Manager) - Recommended

This project includes an `.nvmrc` file that specifies Node.js 24. This provides project-level isolation without affecting your system's Node version.

```bash
# Install nvm if you haven't already
# Visit: https://github.com/nvm-sh/nvm

# In the project directory, install Node.js 24 (one-time setup)
nvm install

# Use the Node.js version specified in .nvmrc (run this each time you work on the project)
nvm use

# Or, install and use in one command
nvm install && nvm use
```

**Note:** The `.nvmrc` file ensures this project uses Node.js 24, while your other projects can use different Node versions. Each terminal session is isolated.

## Installation

```bash
# Install dependencies
npm install
```

## Development

```bash
# Run in development mode with auto-reload
npm run dev

# Build TypeScript
npm run build

# Run compiled version
npm start
```

## Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

## Demo Flows

The demo showcases three key flows:

### 1. Client Enrollment
```bash
npm run demo:enroll
```

### 2. Good Request (properly signed)
```bash
npm run demo:good
```

### 3. Bad Request (tampered body)
```bash
npm run demo:bad
```

## Project Structure

```
src/
├── config/          # Security and environment configuration
├── crypto/          # RFC 9421 and RFC 9530 implementations
├── infra/           # In-memory database
├── middleware/      # Express middleware (signature verification)
├── routes/          # API routes
├── shared/          # Shared utilities and error types
├── client/          # Demo client for testing
└── server.ts        # Main Express server
```

## API Endpoints

### Admin (no signature required)
- `POST /admin/clients` - Create a new client
- `POST /admin/clients/:id/keys` - Register a public key
- `GET /admin/audit` - View verification audit log

### Demo API (signature required)
- `PUT /v1/secrets/:name` - Store a secret value
- `GET /v1/secrets/:name` - Retrieve a secret value

### Utility
- `GET /` - Demo information
- `GET /health` - Health check

## RFCs Implemented

- **[RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421)** - HTTP Message Signatures
- **[RFC 9530](https://datatracker.ietf.org/doc/html/rfc9530)** - Digest Fields
- **[RFC 7807](https://datatracker.ietf.org/doc/html/rfc7807)** - Problem Details
- **[RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)** - JWK Thumbprint

## Libraries Used

- **Express** (47M weekly downloads) - Web framework
- **jose** (19M weekly downloads) - JWK/JOSE utilities
- **Jest** (34.5M weekly downloads) - Testing framework
- **http-message-signatures** by dhensby - RFC 9421 implementation

## License

MIT License - See [LICENSE](LICENSE) file for details.

For demonstration and educational purposes.
