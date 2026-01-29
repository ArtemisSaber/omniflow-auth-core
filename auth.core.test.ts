import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import createApp from '../../../app.js';
import type { Express } from 'express';

describe('Auth Core Module', () => {
  let app: Express;

  beforeAll(async () => {
    app = await createApp();
  });

  it('should have a register endpoint in core', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ email: 'core@example.com', password: 'password123' });
    
    expect(response.status).toBe(200);
    expect(response.body.message).toBe('User registered successfully');
  });

  it('should have a login endpoint in core', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'core@example.com', password: 'password123' });
    
    expect(response.status).toBe(200);
    expect(response.body.message).toBe('User logged in successfully');
    expect(response.body.token).toBeDefined();
  });
});
