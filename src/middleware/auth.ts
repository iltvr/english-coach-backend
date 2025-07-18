import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

dotenv.config();

// Bearer‑token authentication middleware
export function requireApiKey(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (token !== process.env.API_KEY) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  next();
}
