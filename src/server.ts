import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

import { requireApiKey } from './middleware/auth';
// import { verifyRecaptcha } from './utils/recaptcha';

dotenv.config();
const app = express();

// ─── 1. GLOBAL MIDDLEWARE ──────────────────────────────────────────────────────

// 1.1 Secure HTTP headers
app.use(helmet());

// 1.2 CORS (lock down to specific origin in production)
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'https://english-coach.online',
    'https://www.english-coach.online',
    'https://english-coach.pages.dev',
  ],
  credentials: true,
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept'],
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
};

app.use(cors(corsOptions));

// 1.3 JSON body parsing
app.use(express.json());

// Enabling CORS Pre-Flight
app.options('/api/send', cors());

// Example route to test CORS
app.get('/api/healthcheck', (req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

// 1.4 Rate limiting (per IP)
app.use('/api/send', rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS),
  max: Number(process.env.RATE_LIMIT_MAX),
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts, please try again later.'
}));

// ─── 2. MAIL TRANSPORTER SETUP ────────────────────────────────────────────────

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ─── 3. /api/send ROUTE ────────────────────────────────────────────────────────

app.post(
  '/api/send',
  requireApiKey,                  // ◀️ Protect with Bearer API Key
  // ◀️ Validate & sanitize inputs
  [
    // body('recaptchaToken').notEmpty().withMessage('Missing recaptchaToken'),
    body('name')
      .trim()
      .isLength({ min: 1, max: 100 }).withMessage('Name is required (1–100 chars)'),
    body('email')
      .trim()
      .isEmail().withMessage('Valid email required'),
    body('contact').notEmpty().withMessage('Missing contact method'),
    body('timeSlot').notEmpty().withMessage('Missing time slot'),
    body('purpose').notEmpty().withMessage('Missing purpose'),
    body('timeframe').notEmpty().withMessage('Missing timeframe'),
    body('weeklyTime').notEmpty().withMessage('Missing weekly time'),
    body('experience')
      .optional({ checkFalsy: true })
      .trim()
      .isLength({ max: 1000 }).withMessage('Message max length is 1000 chars'),
    body('termsAgreed').isBoolean().withMessage('Terms agreement is required'),
    body('ipAddress').optional({ nullable: true, checkFalsy: true }),
    body('browserInfo').optional({ nullable: true, checkFalsy: true }),
    body('timeZone').optional({ nullable: true, checkFalsy: true })
  ],
  async (req: Request, res: Response) => {
    // 3.1 Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      name,
      email,
      contact,
      message,
      timeSlot,
      purpose,
      timeframe,
      weeklyTime,
      experience,
      termsAgreed,
      // recaptchaToken,
      ipAddress,
      browserInfo,
      timeZone
    } = req.body;

    // 3.2 Verify reCAPTCHA
    // try {
    //   const rc = await verifyRecaptcha(recaptchaToken, req.ip);
    //   if (!rc.success || (rc.score !== undefined && rc.score < Number(process.env.RECAPTCHA_SCORE_THRESHOLD))) {
    //     return res.status(403).json({ error: 'reCAPTCHA verification failed' });
    //   }
    // } catch (err) {
    //   console.error('reCAPTCHA error:', err);
    //   return res.status(500).json({ error: 'reCAPTCHA service error' });
    // }

    // 3.3 Construct safe HTML email
    const safeEexperience = experience
      ? experience.replace(/\n/g, '<br/>')
      : '<em>(no experience provided)</em>';

    const html = `
      <h2>📝 New Application</h2>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Contact:</strong> ${contact}</p>
      <p><strong>Time Slot:</strong> ${timeSlot}</p>
      <p><strong>Purpose:</strong> ${purpose}</p>
      <p><strong>Timeframe:</strong> ${timeframe}</p>
      <p><strong>Weekly Time:</strong> ${weeklyTime}</p>
      <p><strong>Experience:</strong> ${safeEexperience}</p>
      <p><strong>Terms Agreed:</strong> ${termsAgreed}</p>
      <hr/>
      <p><small>
        IP: ${ipAddress} |
        Browser: ${browserInfo} |
        Time Zone: ${timeZone} |
        Sent: ${new Date().toISOString()}
      </small></p>
    `;

    // 3.4 Send email
    try {
      await transporter.sendMail({
        from: `"English Coach Online" <${process.env.FROM_EMAIL}>`,
        to: process.env.TO_EMAIL,
        subject: `New Application from ${name}`,
        html
      });
      return res.sendStatus(200);
    } catch (err: any) {
      console.error('Mail send error:', err);
      if (err.responseCode) {
        console.error('SMTP response code:', err.responseCode);
      }
      return res.status(500).json({ error: 'Failed to send email' });
    }
  }
);

// ─── 4. START SERVER ─────────────────────────────────────────────────────────

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
