import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';

const mockDb = vi.hoisted(() => {
  const state = {
    users: [] as Array<Record<string, unknown>>,
    invitations: [] as Array<Record<string, unknown>>
  };

  return {
    state,
    db: {
      connect: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
      checkHealth: vi.fn(async () => ({ status: 'ok' as const })),
      getClient: vi.fn(() => mockDb.db),
      user: {
        findUnique: vi.fn(async ({ where }: { where: { id?: string; email?: string } }) => {
          if (where.id) {
            return state.users.find(user => user.id === where.id) ?? null;
          }
          if (where.email) {
            return state.users.find(user => user.email === where.email) ?? null;
          }
          return null;
        }),
        findFirst: vi.fn(async ({ where }: { where: { id?: string; email?: string } }) => {
          if (where.id) {
            return state.users.find(user => user.id === where.id) ?? null;
          }
          if (where.email) {
            return state.users.find(user => user.email === where.email) ?? null;
          }
          return null;
        }),
        findMany: vi.fn(async () => [...state.users]),
        create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          const user = {
            id: `user-${state.users.length + 1}`,
            createdAt: new Date(),
            updatedAt: new Date(),
            ...data
          };
          state.users.push(user);
          return user;
        }),
        update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
          const user = state.users.find(entry => entry.id === where.id);
          if (!user) {
            throw new Error('User not found');
          }
          Object.assign(user, data, { updatedAt: new Date() });
          return user;
        })
      },
      invitation: {
        findUnique: vi.fn(async ({ where }: { where: { id?: string; tokenHash?: string } }) => {
          if (where.id) {
            return state.invitations.find(invitation => invitation.id === where.id) ?? null;
          }
          if (where.tokenHash) {
            return state.invitations.find(invitation => invitation.tokenHash === where.tokenHash) ?? null;
          }
          return null;
        }),
        findFirst: vi.fn(async ({ where }: { where: { id?: string; tokenHash?: string } }) => {
          if (where.id) {
            return state.invitations.find(invitation => invitation.id === where.id) ?? null;
          }
          if (where.tokenHash) {
            return state.invitations.find(invitation => invitation.tokenHash === where.tokenHash) ?? null;
          }
          return null;
        }),
        findMany: vi.fn(async () => [...state.invitations]),
        create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          const invitation = {
            id: `invitation-${state.invitations.length + 1}`,
            createdAt: new Date(),
            updatedAt: new Date(),
            usedAt: null,
            revoked: false,
            ...data
          };
          state.invitations.push(invitation);
          return invitation;
        }),
        update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
          const invitation = state.invitations.find(entry => entry.id === where.id);
          if (!invitation) {
            throw new Error('Invitation not found');
          }
          Object.assign(invitation, data, { updatedAt: new Date() });
          return invitation;
        })
      }
    },
    reset: () => {
      state.users = [];
      state.invitations = [];
    }
  };
});

vi.mock('../../../infrastructure/database/index.js', () => ({
  db: mockDb.db,
  resetDatabase: async () => {
    mockDb.reset();
  }
}));

vi.mock('../../../config/index.js', () => ({
  getConfig: vi.fn(() => ({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://localhost/test',
    HTTP_PORT: 3000,
    HTTPS_PORT: 3443,
    JWT_SECRET: 'test-jwt-secret-test-jwt-secret-test-jwt-secret',
    JWT_EXPIRES_IN: '1h',
    IAM_ISSUER_URL: 'https://issuer.example.com',
    IAM_AUDIENCE: 'omniflow-admin',
    IAM_ALLOWED_ORG: 'example-org',
    IAM_ALLOWED_ROLE: 'admin'
  }))
}));

vi.mock('./auth.security.js', () => ({
  hashPassword: vi.fn(async (password: string) => `hash:${password}`),
  verifyPassword: vi.fn(async (password: string, hash: string) => hash === `hash:${password}`),
  signAppJwt: vi.fn(({ userId, role }: { userId: string; role: string }) => `jwt:${userId}:${role}`),
  verifyAppJwt: vi.fn((token: string) => {
    if (token === 'admin-token') {
      return { userId: 'admin-user', role: 'admin' };
    }
    if (token === 'user-token') {
      return { userId: 'user-user', role: 'user' };
    }
    if (token === 'admin-db-token') {
      return { userId: 'admin-user-db', role: 'admin' };
    }
    if (token === 'valid-admin-but-no-db') {
      return { userId: 'missing-user', role: 'admin' };
    }
    throw new Error('invalid token');
  }),
  generateInvitationKey: vi.fn(() => 'invite-raw-1'),
  hashInvitationKey: vi.fn((key: string) => `invite-hash:${key}`),
  verifyInvitationKey: vi.fn((key: string, hash: string) => hash === `invite-hash:${key}`),
  verifyIamIdentityCenterJwt: vi.fn(async (token: string) => {
    if (token === 'valid-iam-token') {
      return { email: 'admin@example.com', organization: 'example-org', role: 'admin' };
    }
    if (token === 'wrong-org-token') {
      return { email: 'admin@example.com', organization: 'other-org', role: 'admin' };
    }
    if (token === 'wrong-role-token') {
      return { email: 'admin@example.com', organization: 'example-org', role: 'viewer' };
    }
    throw new Error('invalid IAM token');
  })
}));

import createApp from '../../../app.js';
import { coreRequest } from './auth.test.utils.js';
const state = mockDb.state;

const future = () => new Date(Date.now() + 60 * 60 * 1000);
const past = () => new Date(Date.now() - 60 * 60 * 1000);

const seedInvitation = (overrides: Partial<Record<string, unknown>> = {}) => {
  const invitation = {
    id: `seeded-invitation-${state.invitations.length + 1}`,
    tokenHash: 'invite-hash:invite-raw-1',
    email: 'user@example.com',
    createdBy: 'admin-user',
    usedAt: null,
    revoked: false,
    expiresAt: future(),
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  };
  state.invitations.push(invitation);
  return invitation;
};

const seedUser = (overrides: Partial<Record<string, unknown>> = {}) => {
  const user = {
    id: `seeded-user-${state.users.length + 1}`,
    email: 'existing@example.com',
    name: 'Existing User',
    passwordHash: 'hash:Password123!',
    role: 'user',
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  };
  state.users.push(user);
  return user;
};

describe('Auth Core Module', () => {
  let app: Express;

  beforeAll(async () => {
    app = await createApp();
  });

  beforeEach(async () => {
    state.users = [];
    state.invitations = [];
    vi.clearAllMocks();
  });

  it('rejects registration without an invitation key', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({ email: 'user@example.com', password: 'Password123!' });

    expect(response.status).toBe(400);
  });

  it('registers a user with a valid invitation key', async () => {
    seedInvitation();

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(201);
    expect(response.body.user).toMatchObject({
      email: 'user@example.com',
      role: 'user'
    });
    expect(response.body.user.passwordHash).toBeUndefined();
    expect(mockDb.db.user.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        email: 'user@example.com',
        role: 'user',
        passwordHash: 'hash:Password123!'
      })
    }));
    expect(mockDb.db.invitation.update).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: expect.any(String) }),
      data: expect.objectContaining({ usedAt: expect.any(Date) })
    }));
  });

  it('rejects registration when the invitation email does not match', async () => {
    seedInvitation({ email: 'other@example.com' });

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(400);
  });

  it('rejects registration when the invitation is expired', async () => {
    seedInvitation({ expiresAt: past() });

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(401);
  });

  it('rejects registration when the invitation is revoked', async () => {
    seedInvitation({ revoked: true });

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(401);
  });

  it('rejects registration when the invitation is already used', async () => {
    seedInvitation({ usedAt: new Date() });

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(401);
  });

  it('rejects registration when the email is already registered', async () => {
    seedUser({ email: 'user@example.com' });
    seedInvitation();

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(409);
  });

  it('logs in a user with valid credentials', async () => {
    seedUser({ id: 'user-1', email: 'user@example.com', passwordHash: 'hash:Password123!', role: 'user' });

    const response = await coreRequest(app)
      .post('/api/auth/login')
      .send({ email: 'user@example.com', password: 'Password123!' });

    expect(response.status).toBe(200);
    expect(response.body.token).toBe('jwt:user-1:user');
  });

  it('rejects login with an incorrect password', async () => {
    seedUser({ id: 'user-1', email: 'user@example.com', passwordHash: 'hash:Password123!', role: 'user' });

    const response = await coreRequest(app)
      .post('/api/auth/login')
      .send({ email: 'user@example.com', password: 'wrong-password' });

    expect(response.status).toBe(401);
  });

  it('registers an admin from a valid IAM Identity Center token', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/admin/register')
      .send({ iamToken: 'valid-iam-token' });

    expect(response.status).toBe(201);
    expect(response.body.user).toMatchObject({
      email: 'admin@example.com',
      role: 'admin'
    });
  });

  it('rejects admin registration when the org does not match', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/admin/register')
      .send({ iamToken: 'wrong-org-token' });

    expect(response.status).toBe(403);
  });

  it('rejects admin registration when the role does not match', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/admin/register')
      .send({ iamToken: 'wrong-role-token' });

    expect(response.status).toBe(403);
  });

  it('promotes existing user to admin on IAM admin registration', async () => {
    // Pre-existing user with role 'user'
    state.users.push({ id: 'existing-user', email: 'admin@example.com', role: 'user', passwordHash: null });

    const response = await coreRequest(app)
      .post('/api/auth/admin/register')
      .send({ iamToken: 'valid-iam-token' });

    expect(response.status).toBe(200);
    expect(response.body.user).toMatchObject({
      email: 'admin@example.com',
      role: 'admin'
    });
    // Verify the user was updated in DB
    const updatedUser = state.users.find(u => u.id === 'existing-user');
    expect(updatedUser?.role).toBe('admin');
  });

  it('allows existing admin to re-register (returns existing)', async () => {
    // Pre-existing admin user
    state.users.push({ id: 'existing-admin', email: 'admin@example.com', role: 'admin', passwordHash: null });

    const response = await coreRequest(app)
      .post('/api/auth/admin/register')
      .send({ iamToken: 'valid-iam-token' });

    expect(response.status).toBe(200);
    expect(response.body.user).toMatchObject({
      email: 'admin@example.com',
      role: 'admin'
    });
  });

  it('creates an invitation for an admin user', async () => {
    state.users.push({ id: 'admin-user-db', email: 'admin@example.com', role: 'admin', passwordHash: null });

    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer admin-db-token')
      .send({ email: 'invitee@example.com', expiresInHours: 48 });

    expect(response.status).toBe(201);
    expect(response.body.invitation).toMatchObject({
      email: 'invitee@example.com'
    });
    expect(response.body.invitation.key).toBe('invite-raw-1');
  });

  it('rejects invitation creation for a non-admin user', async () => {
    state.users.push({ id: 'user-user', email: 'user@example.com', role: 'user', passwordHash: 'hash:Password123!' });

    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer user-token')
      .send({ email: 'invitee@example.com', expiresInHours: 48 });

    expect(response.status).toBe(403);
  });

  it('blocks admin route when user role in DB is not admin (defense in depth)', async () => {
    // Token says 'admin' but DB says 'user' - should be blocked
    // We seed a user with ID 'admin-user' (matching the token's userId) but with role 'user'
    state.users.push({ id: 'admin-user', email: 'admin@example.com', role: 'user', passwordHash: null });

    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer admin-token') // verifyAppJwt returns { userId: 'admin-user', role: 'admin' }
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(403);
  });

  it('blocks admin route when user not found in DB (defense in depth)', async () => {
    // Token is valid but refers to a user ID that doesn't exist in DB
    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer valid-admin-but-no-db')
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(403);
  });

  it('lists invitations for an admin user', async () => {
    state.users.push({ id: 'admin-user', email: 'admin@example.com', role: 'admin', passwordHash: null });
    seedInvitation();

    const response = await coreRequest(app)
      .get('/api/auth/invitations')
      .set('Authorization', 'Bearer admin-token');
    expect(response.status).toBe(200);
    expect(response.body.invitations).toHaveLength(1);
  });

  it('accepts invitation with null email (open invitation)', async () => {
    seedInvitation({ email: null });

    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({
        email: 'user@example.com',
        password: 'Password123!',
        invitationKey: 'invite-raw-1'
      });

    expect(response.status).toBe(201);
  });

  it('creates an invitation with default expiry (24h)', async () => {
    state.users.push({ id: 'admin-user-db', email: 'admin@example.com', role: 'admin', passwordHash: null });

    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer admin-db-token')
      .send({});

    expect(response.status).toBe(201);
    const invitation = response.body.invitation;
    const expiresAt = new Date(invitation.expiresAt);
    const now = new Date();
    const diffHours = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
    expect(diffHours).toBeGreaterThan(23);
    expect(diffHours).toBeLessThan(25);
  });

  it('handles invitation not found on delete', async () => {
    state.users.push({ id: 'admin-user', email: 'admin@example.com', role: 'admin', passwordHash: null });

    const response = await coreRequest(app)
      .delete('/api/auth/invitations/non-existent-id')
      .set('Authorization', 'Bearer admin-token');

    // When invitation doesn't exist, update throws -> 500
    expect(response.status).toBe(500);
  });

  it('rejects request with missing Authorization header', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(401);
  });

  it('rejects request with non-Bearer Authorization header', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Basic dXNlcjpwYXNz')
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(401);
  });

  it('rejects request with empty Bearer token', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearer ')
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(401);
  });

  it('rejects request with malformed Bearer token (no space)', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/invitations')
      .set('Authorization', 'Bearertoken')
      .send({ email: 'invitee@example.com' });

    expect(response.status).toBe(401);
  });
});
