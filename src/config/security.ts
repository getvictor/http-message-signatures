/**
 * Security middleware configuration
 */

import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

/**
 * Helmet configuration for security headers
 */
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
});

/**
 * Rate limiting configuration
 * Prevents abuse by limiting requests per IP
 */
export const rateLimitConfig = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    type: 'https://httpwg.org/specs/rfc9110.html#status.429',
    title: 'Too Many Requests',
    status: 429,
    detail: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
});

/**
 * Body size limits (in bytes)
 */
export const BODY_SIZE_LIMIT = 2 * 1024 * 1024; // 2MB

/**
 * Allowed content types for requests with bodies
 */
export const ALLOWED_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'text/plain',
];
