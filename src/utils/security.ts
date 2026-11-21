import DOMPurify from 'dompurify';

/**
 * Security utilities for the CV Generator.
 *
 * Provides input sanitization, rate limiting, and validation helpers
 * to protect against XSS, rate abuse, and malformed input.
 */

// ---------------------------------------------------------------------------
// 1. HTML Sanitization (XSS Prevention)
// ---------------------------------------------------------------------------

/**
 * Sanitizes HTML strings before rendering them in the DOM.
 * Removes script tags, event handlers, javascript: URLs, and other
 * dangerous constructs while preserving safe formatting (bold, italic,
 * lists, links, etc.).
 */
export function sanitizeHtml(html: string): string {
  if (!html || typeof html !== 'string') return '';
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [
      'b',
      'i',
      'em',
      'strong',
      'u',
      's',
      'p',
      'br',
      'div',
      'span',
      'h1',
      'h2',
      'h3',
      'h4',
      'h5',
      'h6',
      'ul',
      'ol',
      'li',
      'blockquote',
      'pre',
      'code',
      'a',
      'img',
    ],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'target', 'rel'],
    ALLOWED_URI_REGEXP: /^(?:(?:https?:)?|\/)/i,
    FORCE_BODY: false,
  });
}

/**
 * Sanitizes plain text for safe display (no HTML allowed).
 * Escapes all HTML entities.
 */
export function sanitizeText(text: string): string {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Sanitizes a URL for safe use in href/src attributes.
 * Only allows http:, https:, or relative paths.
 */
export function sanitizeUrl(url: string): string {
  if (!url || typeof url !== 'string') return '';
  const trimmed = url.trim();
  if (
    !trimmed.startsWith('http://') &&
    !trimmed.startsWith('https://') &&
    !trimmed.startsWith('/')
  ) {
    return '';
  }
  return trimmed;
}

// ---------------------------------------------------------------------------
// 2. Input Validation
// ---------------------------------------------------------------------------

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validates a name field (max 120 chars, no HTML).
 */
export function validateName(value: string): ValidationResult {
  const errors: string[] = [];
  if (!value || !value.trim()) {
    errors.push('Name is required');
  } else if (value.trim().length < 2) {
    errors.push('Name must be at least 2 characters');
  } else if (value.trim().length > 120) {
    errors.push('Name must be 120 characters or fewer');
  } else if (/[<>&"']/.test(value)) {
    errors.push('Name contains invalid characters');
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Validates an email address.
 */
export function validateEmail(value: string): ValidationResult {
  const errors: string[] = [];
  if (!value || !value.trim()) {
    errors.push('Email is required');
  } else {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value.trim())) {
      errors.push('Invalid email format');
    } else if (value.trim().length > 200) {
      errors.push('Email must be 200 characters or fewer');
    }
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Validates a message/textarea field (max 2000 chars).
 */
export function validateMessage(value: string): ValidationResult {
  const errors: string[] = [];
  if (!value || !value.trim()) {
    errors.push('Message is required');
  } else if (value.trim().length < 5) {
    errors.push('Message must be at least 5 characters');
  } else if (value.trim().length > 2000) {
    errors.push('Message must be 2000 characters or fewer');
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Validates a CV field (max 5000 chars for rich text content).
 */
export function validateCvField(value: string, fieldName: string): ValidationResult {
  const errors: string[] = [];
  if (!value || !value.trim()) {
    errors.push(`${fieldName} is required`);
  } else if (value.trim().length > 5000) {
    errors.push(`${fieldName} must be 5000 characters or fewer`);
  }
  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// 3. Client-Side Rate Limiting
// ---------------------------------------------------------------------------

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitRecord>();

/**
 * Checks if an action is rate-limited and records the attempt.
 *
 * @param key - Unique identifier for the action (e.g., `contact-form:${userId}`)
 * @param maxAttempts - Maximum number of attempts allowed in the window
 * @param windowMs - Time window in milliseconds
 * @returns `{ allowed: boolean; remaining: number; resetTime: number }`
 */
export function checkRateLimit(
  key: string,
  maxAttempts: number = 5,
  windowMs: number = 60_000 // 1 minute default
): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const record = rateLimitStore.get(key);

  if (!record || now > record.resetTime) {
    rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1, resetTime: now + windowMs };
  }

  if (record.count >= maxAttempts) {
    return { allowed: false, remaining: 0, resetTime: record.resetTime };
  }

  record.count++;
  rateLimitStore.set(key, record);
  return { allowed: true, remaining: maxAttempts - record.count, resetTime: record.resetTime };
}

/**
 * Resets the rate limit for a given key (e.g., after successful auth).
 */
export function resetRateLimit(key: string): void {
  rateLimitStore.delete(key);
}

// ---------------------------------------------------------------------------
// 4. Form Submission Guard
// ---------------------------------------------------------------------------

/**
 * Enforces a cooldown between submissions of the same form. Used after a
 * successful submit so a user cannot fire the same form again immediately.
 */
const submissionCooldowns = new Map<string, number>();

/**
 * True when the cooldown for this form has elapsed and another submission is
 * allowed. Guards against double-submits and rapid repeated clicks.
 */
export function isSubmissionAllowed(formKey: string): boolean {
  const readyAt = submissionCooldowns.get(formKey);
  return !readyAt || Date.now() >= readyAt;
}

/**
 * Records that a form submission was made for a given key.
 */
export function recordFormSubmission(formKey: string, cooldownMs: number = 5_000): void {
  submissionCooldowns.set(formKey, Date.now() + cooldownMs);
}

// ---------------------------------------------------------------------------
// 5. Content Security Helpers
// ---------------------------------------------------------------------------

/**
 * Removes any potentially dangerous attributes from HTML attribute strings.
 * Used as an extra layer of defense before rendering user content.
 */
export function sanitizeAttributeValue(value: string): string {
  if (!value || typeof value !== 'string') return '';
  return value
    .replace(/javascript:/gi, '')
    .replace(/data:/gi, '')
    .replace(/vbscript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim();
}

/**
 * Validates and sanitizes a full name for display purposes.
 * Returns the sanitized name or null if invalid.
 */
export function sanitizeName(name: string): string | null {
  const result = validateName(name);
  if (!result.valid) return null;
  return sanitizeText(name.trim());
}

/**
 * Validates and sanitizes an email for display/storage.
 * Returns the sanitized email or null if invalid.
 */
export function sanitizeEmail(email: string): string | null {
  const result = validateEmail(email);
  if (!result.valid) return null;
  return email.trim().toLowerCase();
}

/**
 * Validates and sanitizes a message/textarea for display/storage.
 * Returns the sanitized message or null if invalid.
 */
export function sanitizeMessage(message: string): string | null {
  const result = validateMessage(message);
  if (!result.valid) return null;
  return sanitizeText(message.trim());
}
