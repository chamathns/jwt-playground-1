// Synthetic example for Verify mode. HS256, secret below, issued 2026-10-29, expires 2100-01-01.
// Fixed on purpose so the example never shows as expired; samples.test.js proves it still verifies.
export const SAMPLE_SECRET = 'your-256-bit-secret';
export const SAMPLE_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMjA0MSIsIm5hbWUiOiJBZGEgTG92ZWxhY2UiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3OTMyMzIwMDAsImV4cCI6NDEwMjQ0NDgwMH0.jYFYP2bKKHtjBYMLC2jlfPpUAXHXHDrX0u46a8LNMOE';
