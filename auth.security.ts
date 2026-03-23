import { createHash, createHmac, createPublicKey, randomBytes, scrypt as scryptCallback, timingSafeEqual, verify as verifySignature } from 'crypto';
import { promisify } from 'util';
import { getConfig } from '../../../config/index.js';

const scrypt = promisify(scryptCallback);

const base64UrlEncode = (value: Buffer | string) => Buffer.from(value).toString('base64url');
const base64UrlDecode = (value: string) => Buffer.from(value, 'base64url');

const parseJwtExpiresIn = (expiresIn: string) => {
  const match = /^([1-9]\d*)([smhd])$/.exec(expiresIn.trim());
  if (!match) {
    throw new Error('Invalid JWT expiration format');
  }

  const amount = Number(match[1]!);
  const unit = match[2]! as 's' | 'm' | 'h' | 'd';
  const secondsByUnit = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60
  } as const;

  return amount * secondsByUnit[unit];
};

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

const getAppJwtSecret = () => {
  const config = getConfig();
  if (!config.JWT_SECRET) {
    throw new Error('JWT_SECRET is required');
  }

  return config.JWT_SECRET;
};

export const hashPassword = async (password: string) => {
  const salt = randomBytes(16).toString('base64url');
  const derivedKey = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt$${salt}$${derivedKey.toString('base64url')}`;
};

export const verifyPassword = async (password: string, hash: string) => {
  const [algorithm, salt, encodedKey] = hash.split('$');
  if (algorithm !== 'scrypt' || !salt || !encodedKey) {
    return false;
  }

  const derivedKey = (await scrypt(password, salt, 64)) as Buffer;
  const expectedKey = base64UrlDecode(encodedKey);

  if (derivedKey.length !== expectedKey.length) {
    return false;
  }

  return timingSafeEqual(derivedKey, expectedKey);
};

export const generateInvitationKey = () => randomBytes(24).toString('base64url');
export const hashInvitationKey = (key: string) => sha256(key);
export const verifyInvitationKey = (key: string, hash: string) => sha256(key) === hash;

export type AppJwtPayload = {
  userId: string;
  role: string;
};

export const signAppJwt = (payload: AppJwtPayload) => {
  const config = getConfig();
  const secret = getAppJwtSecret();
  const expiresInSeconds = parseJwtExpiresIn(config.JWT_EXPIRES_IN ?? '24h');
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = {
    sub: payload.userId,
    role: payload.role,
    iat: now,
    exp: now + expiresInSeconds
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedBody = base64UrlEncode(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const signature = createHmac('sha256', secret).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
};

export const verifyAppJwt = (token: string): AppJwtPayload => {
  const secret = getAppJwtSecret();
  const [encodedHeader, encodedBody, encodedSignature] = token.split('.');

  if (!encodedHeader || !encodedBody || !encodedSignature) {
    throw new Error('Invalid token');
  }

  const signingInput = `${encodedHeader}.${encodedBody}`;
  const expectedSignature = createHmac('sha256', secret).update(signingInput).digest();
  const actualSignature = base64UrlDecode(encodedSignature);

  if (expectedSignature.length !== actualSignature.length || !timingSafeEqual(expectedSignature, actualSignature)) {
    throw new Error('Invalid token');
  }

  const payload = JSON.parse(base64UrlDecode(encodedBody).toString('utf8')) as {
    sub?: string;
    role?: string;
    exp?: number;
  };

  if (!payload.sub || !payload.role) {
    throw new Error('Invalid token');
  }

  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }

  return { userId: payload.sub, role: payload.role };
};

type JwkSet = { keys: JwkWithKid[] };
type JwkWithKid = JsonWebKey & { kid: string };

type IdentityClaims = {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  email?: string;
  preferred_username?: string;
  organization?: string;
  role?: string;
};

const jwksCache = new Map<string, { expiresAt: number; jwks: JwkSet }>();

const fetchJwks = async (issuerUrl: string) => {
  const cacheEntry = jwksCache.get(issuerUrl);
  if (cacheEntry && cacheEntry.expiresAt > Date.now()) {
    return cacheEntry.jwks;
  }

  const response = await fetch(new URL('/.well-known/jwks.json', issuerUrl));
  if (!response.ok) {
    throw new Error('Unable to fetch JWKS');
  }

  const jwks = (await response.json()) as JwkSet;
  jwksCache.set(issuerUrl, { jwks, expiresAt: Date.now() + 10 * 60 * 1000 });
  return jwks;
};

export const verifyIamIdentityCenterJwt = async (token: string) => {
  const config = getConfig();
  if (!config.IAM_ISSUER_URL || !config.IAM_AUDIENCE || !config.IAM_ALLOWED_ORG || !config.IAM_ALLOWED_ROLE) {
    throw new Error('IAM Identity Center is not configured');
  }

  const [encodedHeader, encodedBody, encodedSignature] = token.split('.');
  if (!encodedHeader || !encodedBody || !encodedSignature) {
    throw new Error('Invalid IAM token');
  }

  const header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8')) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256' || !header.kid) {
    throw new Error('Invalid IAM token');
  }

  const jwks = await fetchJwks(config.IAM_ISSUER_URL);
  const jwk = jwks.keys.find(key => key.kid === header.kid);
  if (!jwk) {
    throw new Error('Invalid IAM token');
  }

  const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
  const signature = base64UrlDecode(encodedSignature);
  const verified = verifySignature('RSA-SHA256', Buffer.from(`${encodedHeader}.${encodedBody}`), publicKey, signature);

  if (!verified) {
    throw new Error('Invalid IAM token');
  }

  const claims = JSON.parse(base64UrlDecode(encodedBody).toString('utf8')) as IdentityClaims;
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud].filter(Boolean) as string[];

  if (claims.iss !== config.IAM_ISSUER_URL) {
    throw new Error('Invalid IAM token');
  }
  if (!audience.includes(config.IAM_AUDIENCE)) {
    throw new Error('Invalid IAM token');
  }
  if (typeof claims.exp === 'number' && claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Invalid IAM token');
  }

  const email = claims.email ?? claims.preferred_username;
  const organization = claims.organization;
  const role = claims.role;

  if (!email || !organization || !role) {
    throw new Error('Invalid IAM token');
  }

  return {
    email,
    organization,
    role
  };
};
