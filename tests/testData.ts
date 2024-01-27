import { X509Certificate } from '@peculiar/x509';

import { AppInfo } from '../src/attestation';
import { parseUUIDV4 } from '../src/utils';

// Key id generated on test device.
export const KEY_ID = '+7NWLawiwi1lyK6vxqHzUp1bXzMji/Ft89ztMqPW4H4=';
// uuid v4.
export const KEY_ATTESTATION_CHALLENGE_STR =
  '279e8603-7bb9-4c7a-8965-aa1f8d7c16ee';

// Key Attestation generated on test device.
export const ATTESTATION_BASE64 =
  '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';

export const TEST_APP_INFO: AppInfo = {
  appId: '979F6L8R8M.org.reactjs.native.example.RNClientAttest',
  developmentEnv: true,
};

export const EXPECTED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBxvOEkYXjdJPbouGYZZwNN1aaK+Y
tqAC2aStd1CUVnVwk9ntq+U+Jcf3kDaLQTLl7rgPRl3LM8BzvgCz1gNTlw==
-----END PUBLIC KEY-----`;

export const EXPECTED_RECEIPT_BASE64 = `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`;

// Obtained from Apple, but this is just another Cert for testing.
export const WEBAUTHN_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----`;

export const WEBAUTHN_ROOT_CERT = new X509Certificate(WEBAUTHN_ROOT_CERT_PEM);

// Sample JSON request.
export const REQUEST_CHALLENGE_STR = 'b4f75c22-0c58-4e6c-8b32-aa095ff04037';
export const REQUEST = {
  action: 'getGameLevel',
  levelId: 1234,
  challenge: parseUUIDV4(REQUEST_CHALLENGE_STR),
};

// Assertion generated on test device using above request.
export const REQUEST_ASSERTION_BASE64 =
  'omlzaWduYXR1cmVYRzBFAiEA7rXf6ot4kRyKaxmreIr4VIcx6qaJ6OvTqDKrDvGvGVkCIHqa5R9RSoIW15O13Tac+PzS8ygnpDVnrDH946NO3vEZcWF1dGhlbnRpY2F0b3JEYXRhWCVutpyD/zIJtnX/U/J7xsnsNTjZmiJuXJwnMyGt8uSKXUAAAAAB';