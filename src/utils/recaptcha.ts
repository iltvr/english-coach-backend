import fetch from 'node-fetch';
import dotenv from 'dotenv';
dotenv.config();

interface RecaptchaResponse {
  success: boolean;
  score?: number;
  'error-codes'?: string[];
}

// Verify a reCAPTCHA v3 token with Google
export async function verifyRecaptcha(token: string, remoteIp?: string): Promise<RecaptchaResponse> {
  const secret = process.env.RECAPTCHA_SECRET!;
  const params = new URLSearchParams({
    secret,
    response: token,
    ...(remoteIp ? { remoteip: remoteIp } : {})
  });

  const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: params
  });
  return (await res.json()) as RecaptchaResponse;
}
