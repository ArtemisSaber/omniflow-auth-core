import { describe, expect, it, vi, beforeEach } from 'vitest';

// Mock crypto before importing auth.security
vi.mock('crypto', () => ({
  createHash: vi.fn(() => ({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn(() => Buffer.from('hashed'))
  })),
  createHmac: vi.fn(() => ({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn(() => Buffer.from('hmac'))
  })),
  createPublicKey: vi.fn(() => Buffer.from('fake-public-key') as any),
  randomBytes: vi.fn(() => Buffer.from('random')),
  scrypt: vi.fn(() => Promise.resolve(Buffer.from('scrypt-output'))),
  timingSafeEqual: vi.fn(() => true),
  verify: vi.fn(() => true) // verifySignature
}));

// Mock config before importing auth.security
vi.mock('../../../config/index.js', () => ({
  getConfig: vi.fn(() => ({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://localhost/test',
    JWT_SECRET: 'test-jwt-secret',
    JWT_EXPIRES_IN: '24h',
    IAM_ISSUER_URL: undefined,
    IAM_AUDIENCE: undefined,
    IAM_ALLOWED_ORG: undefined,
    IAM_ALLOWED_ROLE: undefined
  }))
}));

import { verifyIamIdentityCenterJwt } from './auth.security.js';
import { getConfig } from '../../../config/index.js';
import { verify as cryptoVerify } from 'crypto';

// Helper to create JWT tokens
function makeJwt(payload: any, alg = 'RS256', kid = 'test-key-id'): string {
  const header = { alg, kid, typ: 'JWT' };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedBody = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = Buffer.from('fakesignature').toString('base64url'); // ensure valid base64url
  return `${encodedHeader}.${encodedBody}.${signature}`;
}

describe('verifyIamIdentityCenterJwt', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Reset fetch
    global.fetch = undefined as any;
  });

  it('should throw when IAM is not configured', async () => {
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      JWT_SECRET: 'test-secret',
      JWT_EXPIRES_IN: '24h',
      IAM_ISSUER_URL: undefined,
      IAM_AUDIENCE: undefined,
      IAM_ALLOWED_ORG: undefined,
      IAM_ALLOWED_ROLE: undefined
    });

    await expect(verifyIamIdentityCenterJwt('token')).rejects.toThrow('IAM Identity Center is not configured');
  });

  it('should throw for invalid token format (missing parts)', async () => {
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: 'https://iam.example.com',
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    await expect(verifyIamIdentityCenterJwt('invalid')).rejects.toThrow('Invalid IAM token');
    await expect(verifyIamIdentityCenterJwt('part1.part2')).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when JWKS fetch fails (network error)', async () => {
    const issuerUrl = 'https://iam-unique.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() => Promise.reject(new Error('Network error')));

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Network error');
  });

  it('should throw when JWKS response is not ok', async () => {
    const issuerUrl = 'https://iam-unique2.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() => Promise.resolve({ ok: false } as any));

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Unable to fetch JWKS');
  });

  it('should throw when JWKS does not have matching kid', async () => {
    const issuerUrl = 'https://iam-unique3.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'other-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when signature verification fails', async () => {
    const issuerUrl = 'https://iam-unique4.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    vi.mocked(cryptoVerify).mockReturnValue(false);

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when token uses non-RS256 algorithm', async () => {
    const issuerUrl = 'https://iam-unique13.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    // Use HS256 instead of RS256
    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'HS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when token header has no kid', async () => {
    const issuerUrl = 'https://iam-unique14.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    // Create token without kid in header
    const header = { alg: 'RS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedBody = Buffer.from(JSON.stringify({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    })).toString('base64url');
    const signature = Buffer.from('fakesignature').toString('base64url');
    const token = `${encodedHeader}.${encodedBody}.${signature}`;

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when issuer does not match', async () => {
    const issuerUrl = 'https://iam-unique5.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const wrongIssuer = 'https://wrong-iam.example.com';
    const token = makeJwt({
      iss: wrongIssuer,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when audience does not match (single)', async () => {
    const issuerUrl = 'https://iam-unique6.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'wrong-audience',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when audience as array does not include allowed audience', async () => {
    const issuerUrl = 'https://iam-unique7.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: ['other-audience'],
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when token is expired', async () => {
    const issuerUrl = 'https://iam-unique8.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: pastExp,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when email is missing', async () => {
    const issuerUrl = 'https://iam-unique9.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    // Missing email and preferred_username
    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when organization is missing', async () => {
    const issuerUrl = 'https://iam-unique10.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      // organization missing
      role: 'admin'
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should throw when role is missing', async () => {
    const issuerUrl = 'https://iam-unique11.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org'
      // role missing
    }, 'RS256', 'test-key');

    await expect(verifyIamIdentityCenterJwt(token)).rejects.toThrow('Invalid IAM token');
  });

  it('should return claims for valid token', async () => {
    const issuerUrl = 'https://iam-unique12.example.com';
    vi.mocked(getConfig).mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://localhost/test',
      IAM_ISSUER_URL: issuerUrl,
      IAM_AUDIENCE: 'omniflow-admin',
      IAM_ALLOWED_ORG: 'example-org',
      IAM_ALLOWED_ROLE: 'admin'
    });

    global.fetch = vi.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: 'test-key', alg: 'RS256' as const }] })
      } as any)
    );

    const token = makeJwt({
      iss: issuerUrl,
      aud: 'omniflow-admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    }, 'RS256', 'test-key');

    const result = await verifyIamIdentityCenterJwt(token);
    expect(result).toEqual({
      email: 'admin@example.com',
      organization: 'example-org',
      role: 'admin'
    });
    expect(global.fetch).toHaveBeenCalledWith(new URL('/.well-known/jwks.json', issuerUrl));
  });
});
