import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { coreRequest } from './auth.test.utils.js';
import createApp from '../../../app.js';
import type { Express } from 'express';
import { resetDatabase } from '../../../infrastructure/database/index.js';

describe('Auth Core Module', () => {
  let app: Express;

  beforeAll(async () => {
    app = await createApp();
  });

  afterAll(async () => {
    await resetDatabase();
  });

  it('should have a register endpoint in core', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/register')
      .send({ email: 'core@example.com', password: 'password123', name: 'Core User' });

    expect(response.status).toBe(201);
    expect(response.body.message).toBe('User registered successfully');
  });

  it('should have a login endpoint in core', async () => {
    const response = await coreRequest(app)
      .post('/api/auth/login')
      .send({ email: 'core@example.com', password: 'password123' });
    
    expect(response.status).toBe(200);
    expect(response.body.message).toBe('User logged in successfully');
    expect(response.body.token).toBeDefined();
  });
});
