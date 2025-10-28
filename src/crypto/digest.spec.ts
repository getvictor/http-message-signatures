import {
  computeDigest,
  parseContentDigest,
  verifyDigest,
  formatContentDigestHeader,
} from './digest.js';

describe('RFC 9530 Content-Digest', () => {
  describe('computeDigest', () => {
    it('should compute SHA-256 digest with correct format', () => {
      const content = 'Hello, World!';
      const digest = computeDigest(content);

      expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
      expect(digest).toContain('sha-256=:');
      expect(digest.endsWith(':')).toBe(true);
    });

    it('should compute consistent digest for same content', () => {
      const content = JSON.stringify({ foo: 'bar' });
      const digest1 = computeDigest(content);
      const digest2 = computeDigest(content);

      expect(digest1).toBe(digest2);
    });

    it('should compute different digests for different content', () => {
      const digest1 = computeDigest('content1');
      const digest2 = computeDigest('content2');

      expect(digest1).not.toBe(digest2);
    });

    it('should handle Buffer input', () => {
      const buffer = Buffer.from('test content', 'utf-8');
      const digest = computeDigest(buffer);

      expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
    });

    it('should support SHA-512 algorithm', () => {
      const content = 'test';
      const digest = computeDigest(content, 'sha-512');

      expect(digest).toMatch(/^sha-512=:[A-Za-z0-9+/=]+:$/);
    });

    it('should handle empty content', () => {
      const digest = computeDigest('');

      expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
    });
  });

  describe('parseContentDigest', () => {
    it('should parse valid Content-Digest header', () => {
      const header = 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:';
      const parsed = parseContentDigest(header);

      expect(parsed).not.toBeNull();
      expect(parsed?.algorithm).toBe('sha-256');
      expect(parsed?.value).toBe('X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=');
    });

    it('should parse SHA-512 digest', () => {
      const header = 'sha-512=:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=:';
      const parsed = parseContentDigest(header);

      expect(parsed).not.toBeNull();
      expect(parsed?.algorithm).toBe('sha-512');
    });

    it('should return null for invalid format', () => {
      expect(parseContentDigest('invalid')).toBeNull();
      expect(parseContentDigest('sha-256=notencoded')).toBeNull();
      expect(parseContentDigest('sha-256:missing-equals:')).toBeNull();
    });

    it('should return null for missing colons', () => {
      expect(parseContentDigest('sha-256=ABC123')).toBeNull();
    });
  });

  describe('verifyDigest', () => {
    it('should verify correct digest', () => {
      const content = 'Hello, World!';
      const digest = computeDigest(content);

      expect(verifyDigest(content, digest)).toBe(true);
    });

    it('should reject incorrect digest', () => {
      const content = 'Hello, World!';
      const wrongDigest = 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:';

      expect(verifyDigest(content, wrongDigest)).toBe(false);
    });

    it('should reject tampered content', () => {
      const originalContent = 'original content';
      const digest = computeDigest(originalContent);
      const tamperedContent = 'tampered content';

      expect(verifyDigest(tamperedContent, digest)).toBe(false);
    });

    it('should handle Buffer content', () => {
      const buffer = Buffer.from('test', 'utf-8');
      const digest = computeDigest(buffer);

      expect(verifyDigest(buffer, digest)).toBe(true);
    });

    it('should verify SHA-512 digest', () => {
      const content = 'test content';
      const digest = computeDigest(content, 'sha-512');

      expect(verifyDigest(content, digest)).toBe(true);
    });

    it('should reject malformed digest header', () => {
      expect(verifyDigest('content', 'invalid-header')).toBe(false);
    });

    it('should reject unsupported algorithm', () => {
      const digest = 'md5=:dGVzdA==:';
      expect(verifyDigest('test', digest)).toBe(false);
    });
  });

  describe('formatContentDigestHeader', () => {
    it('should format header object correctly', () => {
      const content = 'test';
      const header = formatContentDigestHeader(content);

      expect(header).toHaveProperty('Content-Digest');
      expect(header['Content-Digest']).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/);
    });

    it('should format SHA-512 header', () => {
      const content = 'test';
      const header = formatContentDigestHeader(content, 'sha-512');

      expect(header['Content-Digest']).toMatch(/^sha-512=:[A-Za-z0-9+/=]+:$/);
    });
  });

  describe('Integration scenarios', () => {
    it('should verify JSON body digest', () => {
      const body = JSON.stringify({ message: 'Hello', value: 42 });
      const digest = computeDigest(body);

      expect(verifyDigest(body, digest)).toBe(true);
    });

    it('should detect body tampering in JSON', () => {
      const originalBody = JSON.stringify({ amount: 100 });
      const digest = computeDigest(originalBody);

      const tamperedBody = JSON.stringify({ amount: 999999 });

      expect(verifyDigest(tamperedBody, digest)).toBe(false);
    });
  });
});
