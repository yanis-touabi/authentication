export const JWT_CONSTANTS = {
  ACCESS_TOKEN_EXPIRES_IN: '15m',
  REFRESH_TOKEN_EXPIRES_IN: '7d',
  SECRET: process.env.JWT_SECRET || 'fallback-secret-key',
};

export const PASSWORD_CONSTANTS = {
  SALT_ROUNDS: 10,
  MIN_LENGTH: 8,
  MAX_LENGTH: 30,
};

export const VERIFICATION_CONSTANTS = {
  CODE_LENGTH: 6,
  CODE_EXPIRY_MINUTES: 15,
};

export const CACHE_CONSTANTS = {
  BLACKLIST_PREFIX: 'blacklist:',
  REFRESH_TOKEN_PREFIX: 'refresh_token:',
  RESET_CODE_PREFIX: 'reset_code:',
  VERIFIED_PREFIX: 'verified:',
  TOKEN_TTL: 7 * 24 * 60 * 60, // 7 days in seconds
};
