import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { validate } from '../../../middleware/validation.js';
import { db } from '../../../infrastructure/database/index.js';
import { getConfig } from '../../../config/index.js';
import {
  generateInvitationKey,
  hashInvitationKey,
  hashPassword,
  signAppJwt,
  verifyAppJwt,
  verifyIamIdentityCenterJwt,
  verifyPassword
} from './auth.security.js';

const router = Router();

const registerSchema = z.object({
  email: z.email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  invitationKey: z.string().min(1, 'Invitation key is required')
});

const loginSchema = z.object({
  email: z.email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

const adminRegisterSchema = z.object({
  iamToken: z.string().min(1, 'IAM token is required')
});

const createInvitationSchema = z.object({
  email: z.email().optional(),
  expiresInHours: z.number().int().positive().optional()
});


type AuthenticatedRequest = Request & {
  user?: {
    userId: string;
    role: string;
  };
};

const getClient = () => db.getClient();

const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authorization = req.header('authorization');
  const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    req.user = verifyAppJwt(token);
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

const requireAdmin = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const client = getClient();
    const user = await client.user.findUnique({ where: { id: req.user.userId } });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  } catch {
    return res.status(403).json({ error: 'Forbidden' });
  }
};

const serializeInvitation = (invitation: {
  id: string;
  email?: string | null;
  createdBy: string;
  usedAt?: Date | null;
  revoked?: boolean;
  expiresAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}) => ({
  id: invitation.id,
  email: invitation.email ?? null,
  createdBy: invitation.createdBy,
  usedAt: invitation.usedAt ?? null,
  revoked: invitation.revoked ?? false,
  expiresAt: invitation.expiresAt,
  createdAt: invitation.createdAt,
  updatedAt: invitation.updatedAt
});

router.post('/register', validate(registerSchema), async (req: Request, res: Response) => {
  const { email, password, invitationKey } = req.body as z.infer<typeof registerSchema>;

  const client = getClient();
  const invitation = await client.invitation.findUnique({
    where: { tokenHash: hashInvitationKey(invitationKey) }
  });

  if (!invitation) {
    return res.status(401).json({ error: 'Invalid invitation key' });
  }

  if (invitation.revoked) {
    return res.status(401).json({ error: 'Invitation is revoked' });
  }

  if (invitation.usedAt) {
    return res.status(401).json({ error: 'Invitation is already used' });
  }

  if (new Date(invitation.expiresAt).getTime() < Date.now()) {
    return res.status(401).json({ error: 'Invitation has expired' });
  }

  if (invitation.email && invitation.email !== email) {
    return res.status(400).json({ error: 'Invitation email does not match' });
  }

  const existingUser = await client.user.findUnique({ where: { email } });
  if (existingUser) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const passwordHash = await hashPassword(password);
  const user = await client.user.create({
    data: {
      email,
      passwordHash,
      role: 'user'
    }
  });

  await client.invitation.update({
    where: { id: invitation.id },
    data: { usedAt: new Date() }
  });

  return res.status(201).json({
    message: 'User registered successfully',
    user: {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
      role: user.role ?? 'user'
    }
  });
});

router.post('/login', validate(loginSchema), async (req: Request, res: Response) => {
  const { email, password } = req.body as z.infer<typeof loginSchema>;
  const client = getClient();
  const user = await client.user.findUnique({ where: { email } });

  if (!user?.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const matches = await verifyPassword(password, user.passwordHash);
  if (!matches) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = signAppJwt({
    userId: user.id,
    role: user.role ?? 'user'
  });

  return res.status(200).json({
    message: 'User logged in successfully',
    token
  });
});

router.post('/admin/register', validate(adminRegisterSchema), async (req: Request, res: Response) => {
  const { iamToken } = req.body as z.infer<typeof adminRegisterSchema>;
  const config = getConfig();
  const claims = await verifyIamIdentityCenterJwt(iamToken);

  if (claims.organization !== config.IAM_ALLOWED_ORG) {
    return res.status(403).json({ error: 'Organization not allowed' });
  }

  if (claims.role !== config.IAM_ALLOWED_ROLE) {
    return res.status(403).json({ error: 'Role not allowed' });
  }

  const client = getClient();
  const existingUser = await client.user.findUnique({ where: { email: claims.email } });
  if (existingUser) {
    if (existingUser.role !== 'admin') {
      const user = await client.user.update({
        where: { id: existingUser.id },
        data: { role: 'admin' }
      });
      return res.status(200).json({
        message: 'Admin account updated successfully',
        user: {
          id: user.id,
          email: user.email,
          role: user.role ?? 'admin'
        }
      });
    }

    return res.status(200).json({
      message: 'Admin already registered',
      user: {
        id: existingUser.id,
        email: existingUser.email,
        role: existingUser.role
      }
    });
  }

  const user = await client.user.create({
    data: {
      email: claims.email,
      name: claims.email.split('@')[0] ?? null,
      passwordHash: null,
      role: 'admin'
    }
  });

  return res.status(201).json({
    message: 'Admin registered successfully',
    user: {
      id: user.id,
      email: user.email,
      role: user.role ?? 'admin'
    }
  });
});

router.post('/invitations', requireAuth, requireAdmin, validate(createInvitationSchema), async (req: Request, res: Response) => {
  const { email, expiresInHours } = req.body as z.infer<typeof createInvitationSchema>;
  const client = getClient();
  const key = generateInvitationKey();
  const invitation = await client.invitation.create({
    data: {
      tokenHash: hashInvitationKey(key),
      email: email ?? null,
      createdBy: req.user!.userId,
      expiresAt: new Date(Date.now() + (expiresInHours ?? 24) * 60 * 60 * 1000)
    }
  });

  return res.status(201).json({
    message: 'Invitation created successfully',
    invitation: {
      ...serializeInvitation(invitation),
      key
    }
  });
});

router.get('/invitations', requireAuth, requireAdmin, async (_req: Request, res: Response) => {
  const client = getClient();
  const invitations = await client.invitation.findMany();

  return res.status(200).json({
    invitations: invitations.map(serializeInvitation)
  });
});

router.delete('/invitations/:id', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const id = req.params['id'];
  if (typeof id !== 'string') {
    return res.status(400).json({ error: 'Missing invitation id' });
  }
  const client = getClient();
  const invitation = await client.invitation.update({
    where: { id },
    data: { revoked: true }
  });

  return res.status(200).json({
    message: 'Invitation revoked successfully',
    invitation: serializeInvitation(invitation)
  });
});

export default router;
