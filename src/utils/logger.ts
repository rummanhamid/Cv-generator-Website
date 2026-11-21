/**
 * Secure logging utility.
 *
 * All log output is suppressed in production builds (when
 * import.meta.env.PROD is true) to prevent leaking sensitive
 * information to the browser console.
 */

const isDev = import.meta.env.DEV;

/**
 * Logs an error message. Only visible in development mode.
 */
export function logError(message: string, error?: unknown): void {
  if (isDev) {
    console.error(`[CV Generator Error] ${message}`, error);
  }
}

/**
 * Logs a warning message. Only visible in development mode.
 */
export function logWarn(message: string): void {
  if (isDev) {
    console.warn(`[CV Generator Warn] ${message}`);
  }
}

/**
 * Logs an info message. Only visible in development mode.
 */
export function logInfo(message: string): void {
  if (isDev) {
    console.info(`[CV Generator Info] ${message}`);
  }
}

/**
 * Logs a debug message. Only visible in development mode.
 */
export function logDebug(message: string): void {
  if (isDev) {
    console.debug(`[CV Generator Debug] ${message}`);
  }
}
