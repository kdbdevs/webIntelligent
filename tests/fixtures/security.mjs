import {
  responseSecurityMetadata,
  requestSecurityMetadata,
} from '../../server/security-metadata.mjs';
// Synthetic metadata only: these URLs are NEVER fetched. This allows transport-policy
// cases without weakening collector DNS/private-network controls for a test server.
export const safeHeaders = [
  {
    name: 'Content-Security-Policy',
    value: "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
  },
  { name: 'X-Content-Type-Options', value: 'nosniff' },
  { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
];
export function request(overrides = {}) {
  return {
    id: 'r-fixture',
    url: 'https://app.example.test/page',
    documentUrl: 'https://app.example.test/page',
    pageUrl: 'https://app.example.test/page',
    mainFrame: true,
    navigation: true,
    resourceType: 'document',
    status: 200,
    responseType: 'text/html',
    method: 'GET',
    parameters: [],
    queryParameters: [],
    security: responseSecurityMetadata(safeHeaders),
    requestSecurity: requestSecurityMetadata({}),
    ...overrides,
  };
}
export const positiveRequests = [
  request({
    id: 'r-headers',
    security: responseSecurityMetadata([
      { name: 'Set-Cookie', value: '__Host-session=SECRET_COOKIE; SameSite=None; Path=/sub' },
    ]),
  }),
  request({
    id: 'r-transfer',
    resourceType: 'fetch',
    navigation: false,
    url: 'http://recipient.example.test/collect?token=%5Bomitted%5D',
    method: 'POST',
    parameters: [
      { name: 'token', location: 'query', type: 'string', value: '[omitted]' },
      { name: 'email', location: 'JSON body', type: 'string', value: '[omitted]' },
    ],
    requestSecurity: requestSecurityMetadata({ authorization: 'Bearer SECRET_AUTH' }),
  }),
];
