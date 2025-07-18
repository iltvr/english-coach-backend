// server.ts
import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

import { requireApiKey } from './middleware/auth';

dotenv.config();
const app = express();

// ─── 1. SECURITY MIDDLEWARE ────────────────────────────────────────────────────

// 1.1 Secure HTTP headers
app.use(helmet());

// 1.2 CORS: allow only your frontend + handle OPTIONS preflight
const FRONTEND = process.env.NODE_ENV === 'production'
  ? process.env.CORS_ORIGIN!
  : '*';

app.use(cors({
  origin: FRONTEND,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));
// Explicitly handle OPTIONS for all routes
app.options('*', cors());

// 1.3 JSON body parsing
app.use(express.json());

// 1.4 Rate‑limiting on the send endpoint
app.use('/api/send', rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,
  max: Number(process.env.RATE_LIMIT_MAX) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests—please try again later.'
}));

// ─── 2. MAIL TRANSPORTER ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST!,
  port: Number(process.env.SMTP_PORT!),
  auth: {
    user: process.env.SMTP_USER!,
    pass: process.env.SMTP_PASS!
  }
});

// ─── 3. /api/send ROUTE ────────────────────────────────────────────────────────
app.post(
  '/api/send',
  requireApiKey,  // Bearer API‑Key auth

  // Input validation & sanitization
  [
    body('name')
      .trim()
      .isLength({ min: 1, max: 100 }).withMessage('Name is required (1–100 chars)'),
    body('email')
      .trim()
      .isEmail().withMessage('Valid email required'),
    body('contact')
      .trim()
      .notEmpty().withMessage('Contact is required'),
    body('timeSlot')
      .trim()
      .notEmpty().withMessage('Time slot is required'),
    body('purpose')
      .trim()
      .isLength({ max: 1000 }).withMessage('Purpose max length is 1000 chars'),
    body('timeframe')
      .trim()
      .notEmpty().withMessage('Timeframe is required'),
    body('weeklyTime')
      .trim()
      .notEmpty().withMessage('Weekly time is required'),
    body('experience')
      .trim()
      .isLength({ max: 1000 }).withMessage('Experience max length is 1000 chars'),
    body('termsAgreed')
      .isBoolean().withMessage('Terms agreement must be true/false'),
    // Optional metadata (sent from frontend)
    body('ipAddress').optional().isString(),
    body('browserInfo').optional().isString(),
    body('timeZone').optional().isString(),
    body('submissionTime').optional().isISO8601()
  ],

  async (req: Request, res: Response) => {
    // 3.1 Validation check
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // 3.2 Destructure validated fields
    const {
      name,
      email,
      contact,
      timeSlot,
      purpose,
      timeframe,
      weeklyTime,
      experience,
      termsAgreed,
      ipAddress,
      browserInfo,
      timeZone,
      submissionTime
    } = req.body;

    // 3.3 Build HTML email
    const html = `
      <h2>📝 New Application</h2>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Contact:</strong> ${contact}</p>
      <p><strong>Time Slot:</strong> ${timeSlot}</p>
      <p><strong>Purpose:</strong>
        ${purpose ? purpose.replace(/\n/g, '<br/>') : '<em>(none)</em>'}
      </p>
      <p><strong>Timeframe:</strong> ${timeframe}</p>
      <p><strong>Weekly Time:</strong> ${weeklyTime}</p>
      <p><strong>Experience:</strong><br/>
        ${experience ? experience.replace(/\n/g, '<br/>') : '<em>(none)</em>'}
      </p>
      <p><strong>Terms Agreed:</strong> ${termsAgreed}</p>
      <hr/>
      <p><small>
        IP: ${ipAddress} |
        Browser: ${browserInfo} |
        Time Zone: ${timeZone} |
        Sent: ${submissionTime ? new Date(submissionTime).toLocaleString() : new Date().toLocaleString()}
      </small></p>
    `;

    // 3.4 Send via SMTP2GO
    try {
      await transporter.sendMail({
        from: `"No‑Reply" <${process.env.FROM_EMAIL}>`,
        to: process.env.TO_EMAIL,
        subject: `New Application from ${name}`,
        html
      });
      return res.sendStatus(200);
    } catch (err) {
      console.error('Mail send error:', err);
      return res.status(500).json({ error: 'Failed to send email' });
    }
  }
);

// ─── 4. START SERVER ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});

