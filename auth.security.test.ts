import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  generateInvitationKey,
  hashInvitationKey,
  verifyInvitationKey,
  signAppJwt,
  verifyAppJwt
} from './auth.security.js';
import { getConfig } from '../../../config/index.js';

// Mock the config module
vi.mock('../../../config/index.js', () => ({
  getConfig: vi.fn(() => ({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://localhost/test',
    JWT_SECRET: 'test-jwt-secret-12345',
    JWT_EXPIRES_IN: '24h'
  }))
}));

describe('Auth Security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('hashPassword()', () => {
    it('should generate a hash with scrypt algorithm prefix', async () => {
      const hash = await hashPassword('password123');
      expect(hash).toMatch(/^scrypt\$/);
      expect(hash.split('$').length).toBe(3);
    });

    it('should generate different hashes for same password (random salt)', async () => {
      const hash1 = await hashPassword('password123');
      const hash2 = await hashPassword('password123');
      expect(hash1).not.toBe(hash2);
      expect(await verifyPassword('password123', hash1)).toBe(true);
      expect(await verifyPassword('password123', hash2)).toBe(true);
    });

    it('should handle empty password', async () => {
      const hash = await hashPassword('');
      expect(hash).toMatch(/^scrypt\$/);
      expect(await verifyPassword('', hash)).toBe(true);
    });
  });

  describe('verifyPassword()', () => {
    it('should return true for valid password', async () => {
      const hash = await hashPassword('password123');
      expect(await verifyPassword('password123', hash)).toBe(true);
    });

    it('should return false for invalid password', async () => {
      const hash = await hashPassword('password123');
      expect(await verifyPassword('wrongpassword', hash)).toBe(false);
    });

    it('should return false for invalid hash format', async () => {
      expect(await verifyPassword('password', 'invalidhash')).toBe(false);
      expect(await verifyPassword('password', 'scrypt$salt')).toBe(false);
      expect(await verifyPassword('password', 'scrypt$$key')).toBe(false);
      expect(await verifyPassword('password', 'scrypt$salt$')).toBe(false);
    });
  });

  describe('generateInvitationKey()', () => {
    it('should generate a random base64url string', () => {
      const key = generateInvitationKey();
      expect(key.length).toBeGreaterThan(20);
      expect(key).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate unique keys', () => {
      const key1 = generateInvitationKey();
      const key2 = generateInvitationKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe('hashInvitationKey()', () => {
    it('should produce a consistent SHA256 hash', () => {
      const key = 'my-invitation-key';
      const hash = hashInvitationKey(key);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce same hash for same input', () => {
      const key = 'my-invitation-key';
      expect(hashInvitationKey(key)).toBe(hashInvitationKey(key));
    });

    it('should produce different hashes for different inputs', () => {
      expect(hashInvitationKey('key1')).not.toBe(hashInvitationKey('key2'));
    });
  });

  describe('verifyInvitationKey()', () => {
    it('should return true for valid key and hash', () => {
      const key = 'my-invitation-key';
      const hash = hashInvitationKey(key);
      expect(verifyInvitationKey(key, hash)).toBe(true);
    });

    it('should return false for invalid key', () => {
      const key = 'my-invitation-key';
      const hash = hashInvitationKey(key);
      expect(verifyInvitationKey('wrong-key', hash)).toBe(false);
    });

    it('should return false for invalid hash', () => {
      expect(verifyInvitationKey('key', 'invalid-hash')).toBe(false);
    });
  });

  describe('signAppJwt()', () => {
    it('should generate a valid JWT with three parts', () => {
      const token = signAppJwt({ userId: 'user-123', role: 'admin' });
      expect(token.split('.').length).toBe(3);
    });

    it('should include correct payload data', () => {
      const token = signAppJwt({ userId: 'user-123', role: 'admin' });
      const [, encodedBody] = token.split('.');
      const body = JSON.parse(Buffer.from(encodedBody, 'base64url').toString('utf8'));

      expect(body.sub).toBe('user-123');
      expect(body.role).toBe('admin');
      expect(body.iat).toBeDefined();
      expect(body.exp).toBeDefined();
      expect(body.exp).toBeGreaterThan(body.iat);
    });

    it('should have correct header with HS256 algorithm', () => {
      const token = signAppJwt({ userId: 'user-123', role: 'admin' });
      const [encodedHeader] = token.split('.');
      const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));

      expect(header.alg).toBe('HS256');
      expect(header.typ).toBe('JWT');
    });
  });

  describe('verifyAppJwt()', () => {
    it('should verify a valid token and return payload', () => {
      const payload = { userId: 'user-123', role: 'admin' };
      const token = signAppJwt(payload);
      const result = verifyAppJwt(token);
      expect(result).toEqual(payload);
    });

    it('should throw for token with missing parts', () => {
      expect(() => verifyAppJwt('invalid')).toThrow('Invalid token');
      expect(() => verifyAppJwt('part1.part2')).toThrow('Invalid token');
      expect(() => verifyAppJwt('.part2.part3')).toThrow('Invalid token');
    });

    it('should throw for token with invalid signature', () => {
      const token = 'header.body.invalidsignature';
      expect(() => verifyAppJwt(token)).toThrow('Invalid token');
    });

    it('should throw for an expired token', () => {
      const payload = { userId: 'user-123', role: 'admin' };
      const token = signAppJwt(payload);
      const now = Date.now();
      const dateNowSpy = vi.spyOn(Date, 'now').mockReturnValue(now + 25 * 60 * 60 * 1000);

      try {
        expect(() => verifyAppJwt(token)).toThrow('Token expired');
      } finally {
        dateNowSpy.mockRestore();
      }
    });

    it('should verify a token before expiration', () => {
      const payload = { userId: 'user-123', role: 'admin' };
      const token = signAppJwt(payload);
      expect(verifyAppJwt(token)).toEqual(payload);
    });
  });

  describe('signAppJwt() with config', () => {
    const defaultConfig = {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      JWT_SECRET: 'test-jwt-secret',
      JWT_EXPIRES_IN: '24h',
      IAM_ISSUER_URL: undefined,
      IAM_AUDIENCE: undefined,
      IAM_ALLOWED_ORG: undefined,
      IAM_ALLOWED_ROLE: undefined
    };

    afterEach(() => {
      vi.mocked(getConfig).mockReset();
    });

    it('should throw for invalid JWT_EXPIRES_IN format (missing unit)', () => {
      vi.mocked(getConfig).mockReturnValue({
        ...defaultConfig,
        JWT_EXPIRES_IN: '10'
      });

      expect(() => signAppJwt({ userId: 'u', role: 'admin' })).toThrow('Invalid JWT expiration format');
    });

    it('should throw for invalid JWT_EXPIRES_IN format (zero)', () => {
      vi.mocked(getConfig).mockReturnValue({
        ...defaultConfig,
        JWT_EXPIRES_IN: '0s'
      });

      expect(() => signAppJwt({ userId: 'u', role: 'admin' })).toThrow('Invalid JWT expiration format');
    });

    it('should throw for invalid JWT_EXPIRES_IN format (unknown unit)', () => {
      vi.mocked(getConfig).mockReturnValue({
        ...defaultConfig,
        JWT_EXPIRES_IN: '10x'
      });

      expect(() => signAppJwt({ userId: 'u', role: 'admin' })).toThrow('Invalid JWT expiration format');
    });

    it('should respect custom valid JWT_EXPIRES_IN (e.g., 1h)', () => {
      vi.mocked(getConfig).mockReturnValue({
        ...defaultConfig,
        JWT_EXPIRES_IN: '1h'
      });

      const token = signAppJwt({ userId: 'u', role: 'admin' });
      const [, encodedBody] = token.split('.');
      const body = JSON.parse(Buffer.from(encodedBody, 'base64url').toString('utf8'));

      const expectedExp = body.iat + 3600;
      expect(body.exp).toBe(expectedExp);
    });
  });
});
