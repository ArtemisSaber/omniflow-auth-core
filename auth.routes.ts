import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validate } from '../../../middleware/validation.js';

const router = Router();

// Validation schemas
const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  name: z.string().min(1, 'Name is required')
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

router.post("/register", validate(registerSchema), (req: Request, res: Response) => {
  // In a real implementation, you'd create the user and return the created record
  const { email, name } = req.body;
  res.status(201).json({
    message: "User registered successfully",
    user: { id: 1, email, name }
  });
});

router.post("/login", validate(loginSchema), (_req: Request, res: Response) => {
  // In a real implementation, you'd validate credentials and return a JWT
  res.json({
    message: "User logged in successfully",
    token: "mock-jwt-token"
  });
});

export default router;
