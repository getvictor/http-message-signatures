/**
 * HTTP Message Signatures Demo Server
 * Main Express server with security middleware
 */

import express, { type Request, type Response } from 'express';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { helmetConfig, rateLimitConfig, BODY_SIZE_LIMIT } from './config/security.js';
import { db } from './infra/db.js';
import adminRoutes from './routes/admin.routes.js';
import demoRoutes from './routes/demo.routes.js';
import { verifySignatureMiddleware } from './middleware/verify-signature.js';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss',
      ignore: 'pid,hostname',
    },
  },
});

const app = express();
const PORT = process.env.PORT || 3000;

// Logging middleware
app.use(
  pinoHttp({
    logger,
    // Don't log request bodies (security best practice)
    redact: {
      paths: ['req.body', 'res.body'],
      remove: true,
    },
  })
);

// Security middleware
app.use(helmetConfig);
app.use(rateLimitConfig);

// Body parsing middleware with raw body support
// We need raw body for Content-Digest verification
app.use(
  express.json({
    limit: BODY_SIZE_LIMIT,
    verify: (req: any, res, buf, encoding) => {
      // Store raw body for signature verification
      req.rawBody = buf.toString((encoding as BufferEncoding) || 'utf-8');
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: BODY_SIZE_LIMIT,
    verify: (req: any, res, buf, encoding) => {
      req.rawBody = buf.toString((encoding as BufferEncoding) || 'utf-8');
    },
  })
);

// Add rawBody type to Request
declare global {
  namespace Express {
    interface Request {
      rawBody?: string;
      identity?: {
        clientId: string;
        kid: string;
      };
    }
  }
}

/**
 * Root endpoint - Demo information
 */
app.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'HTTP Message Signatures Demo',
    description: 'RFC 9421 HTTP Message Signatures demonstration server',
    version: '1.0.0',
    endpoints: {
      admin: {
        'POST /admin/clients': 'Create a new client',
        'POST /admin/clients/:id/keys': 'Register a public key',
        'GET /admin/audit': 'View audit log',
      },
      demo: {
        'PUT /v1/secrets/:name': 'Store a secret (requires signature)',
        'GET /v1/secrets/:name': 'Retrieve a secret (requires signature)',
      },
      utility: {
        'GET /': 'This information page',
        'GET /health': 'Health check',
      },
    },
    documentation: 'https://datatracker.ietf.org/doc/html/rfc9421',
  });
});

/**
 * Health check endpoint
 */
app.get('/health', (req: Request, res: Response) => {
  const stats = db.getStats();

  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: stats,
  });
});

/**
 * API Routes
 */
app.use('/admin', adminRoutes);

// Demo routes require signature verification
app.use('/v1', verifySignatureMiddleware, demoRoutes);

/**
 * Error handling middleware
 */
app.use((err: any, req: Request, res: Response, next: any) => {
  logger.error({ err }, 'Unhandled error');

  res.status(err.status || 500).json({
    type: 'https://httpwg.org/specs/rfc9110.html#status.500',
    title: 'Internal Server Error',
    status: err.status || 500,
    detail: err.message || 'An unexpected error occurred',
  });
});

/**
 * 404 handler
 */
app.use((req: Request, res: Response) => {
  res.status(404).json({
    type: 'https://httpwg.org/specs/rfc9110.html#status.404',
    title: 'Not Found',
    status: 404,
    detail: `Cannot ${req.method} ${req.path}`,
  });
});

/**
 * Start the server
 */
function start() {
  app.listen(PORT, () => {
    logger.info(`🚀 Server started on http://localhost:${PORT}`);
    logger.info('📚 Documentation: https://datatracker.ietf.org/doc/html/rfc9421');
    logger.info('');
    logger.info('Endpoints:');
    logger.info(`  GET  http://localhost:${PORT}/          - Demo information`);
    logger.info(`  GET  http://localhost:${PORT}/health    - Health check`);
    logger.info('');
    logger.info('Ready for demo! 🎬');
  });
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  start();
}

export { app, start };
