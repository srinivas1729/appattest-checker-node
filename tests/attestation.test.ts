import { Buffer } from 'buffer';
import { randomUUID } from 'crypto';

import {
  AppInfo,
  checkAAGuidPerStep8,
  checkCredentialIdPerStep9,
  checkRPIdPerStep6,
  checkSignCountPerStep7,
  computeAndCheckNoncePerStep2To4,
  checkCertificatesPerStep1,
  parseAttestation,
  setNonceExtensionOID,
  VerificationInputs,
  setAppAttestRootCertificate,
  verifyAttestation,
} from '../src/attestation';
import { getSHA256, parseUUIDV4 } from '../src/utils';
import { X509Certificate } from '@peculiar/x509';

const KEY_ID = 'ZfmvM3RN5QdARrw/bwUAiOrX+21FYXp71q4aiCeKZf0=';
// uuid v4.
const SERVER_CHALLENGE_STR = '279e8603-7bb9-4c7a-8965-aa1f8d7c16ee';

const ATTESTATION_BASE64 =
  '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';

const TEST_APP_INFO: AppInfo = {
  appId: '979F6L8R8M.org.reactjs.native.example.RNClientAttest',
  developmentEnv: true,
};

const EXPECTED_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQqL1r69jhMMk4Yl8G45kwhPw9PQw
HWtcOZsCBLFNE1cvsdxzntUFVnqE6mav5qZLlHjfyRPC4fIHrNwqdwTZMA==
-----END PUBLIC KEY-----`;

const EXPECTED_RECEIPT_BASE64 = `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`;

const WEBAUTHN_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
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

const WEBAUTHN_ROOT_CERT = new X509Certificate(WEBAUTHN_ROOT_CERT_PEM);

describe('verifyAttestation', () => {
  const rawAttestation = Buffer.from(ATTESTATION_BASE64, 'base64');
  const rawServerChallenge = parseUUIDV4(SERVER_CHALLENGE_STR);

  test('passes with valid input', async () => {
    expect(
      await verifyAttestation(
        TEST_APP_INFO,
        KEY_ID,
        rawServerChallenge,
        rawAttestation,
      ),
    ).toEqual({
      result: 'pass',
      publicKeyPem: EXPECTED_PUBLIC_KEY_PEM,
      receipt: Buffer.from(EXPECTED_RECEIPT_BASE64, 'base64'),
    });
  });

  test('fails if challenge is invalid', async () => {
    expect(
      await verifyAttestation(
        TEST_APP_INFO,
        KEY_ID,
        parseUUIDV4(randomUUID()),
        rawAttestation,
      ),
    ).toEqual({
      result: 'fail_nonce_mismatch',
    });
  });

  test('fails if appId is invalid', async () => {
    expect(
      await verifyAttestation(
        { appId: 'random', developmentEnv: false },
        KEY_ID,
        rawServerChallenge,
        rawAttestation,
      ),
    ).toEqual({
      result: 'fail_rpId_mismatch',
    });
  });

  test('fails with keyId mismatch', async () => {
    expect(
      await verifyAttestation(
        TEST_APP_INFO,
        'random_key_id',
        rawServerChallenge,
        rawAttestation,
      ),
    ).toEqual({
      result: 'fail_credId_mismatch',
    });
  });
});

describe('VerificationStep tests', () => {
  let testInputs: VerificationInputs;

  beforeEach(async () => {
    const parseResult = await parseAttestation(
      Buffer.from(ATTESTATION_BASE64, 'base64'),
    );
    if (typeof parseResult === 'string') {
      throw new Error('ParsedAttestation expected!');
    }
    testInputs = {
      appInfo: TEST_APP_INFO,
      keyId: KEY_ID,
      challenge: parseUUIDV4(SERVER_CHALLENGE_STR),
      parsedAttestation: parseResult,
    };
  });

  describe('checkCredentialIdPerStep9', () => {
    const updateCredIdLen = (len: number) => {
      const authData = testInputs.parsedAttestation.authData;
      const credIdLen = authData.subarray(53, 57);
      if (len < 0 || len > 255) {
        throw new Error(`Invalid len: ${len}`);
      }
      credIdLen[1] = Math.floor(len);
    };

    const updateCredId = (keyIdBase64: string) => {
      const authData = testInputs.parsedAttestation.authData;
      const keyIdBuff = Buffer.from(keyIdBase64, 'base64');
      if (keyIdBuff.byteLength != 32) {
        throw new Error('keyIdBase64 is not 32 bytes!');
      }
      keyIdBuff.copy(authData, 55);
    };

    test('passes with valid keyId', async () => {
      expect(await checkCredentialIdPerStep9(testInputs)).toEqual('pass');
    });

    test('fails with keyId mismatch', async () => {
      const fakeKeyId = Buffer.from(KEY_ID, 'base64');
      fakeKeyId[0] ^= 0xff;
      updateCredId(fakeKeyId.toString('base64'));
      expect(await checkCredentialIdPerStep9(testInputs)).toEqual(
        'fail_credId_mismatch',
      );
    });

    test('fails if credIdLen is not 32', async () => {
      updateCredIdLen(24);
      expect(await checkCredentialIdPerStep9(testInputs)).toEqual(
        'fail_credId_len_invalid',
      );
    });
  });

  describe('checkAAGuidPerStep8', () => {
    const updateAAGuidForProd = () => {
      const authData = testInputs.parsedAttestation.authData;
      const aaGuid = authData.subarray(37, 53);
      aaGuid.subarray(9).fill(0);
    };

    test('passes if App Attest guid matches', async () => {
      expect(await checkAAGuidPerStep8(testInputs)).toEqual('pass');
    });

    test('fails if App Attest guid does not matches', async () => {
      updateAAGuidForProd();
      expect(await checkAAGuidPerStep8(testInputs)).toEqual(
        'fail_aaguid_mismatch',
      );
    });
  });

  describe('checkSignCountPerStep7', () => {
    test('passes if signCount is 0', async () => {
      expect(await checkSignCountPerStep7(testInputs)).toEqual('pass');
    });

    test('fails if signCount is not 0', async () => {
      const counter = testInputs.parsedAttestation.authData.subarray(33, 37);
      counter.fill(1);

      expect(await checkSignCountPerStep7(testInputs)).toEqual(
        'fail_signCount_nonZero',
      );
    });
  });

  describe('checkRPIdPerStep6', () => {
    test('passes if rpId matches sha256 of appId', async () => {
      expect(await checkRPIdPerStep6(testInputs)).toEqual('pass');
    });

    test('fails if rpId does not match sha256 of appId', async () => {
      const fakeAppId = 'fakeAppId';
      const fakeAppIdHash = await getSHA256(Buffer.from(fakeAppId));
      if (fakeAppIdHash.byteLength !== 32) {
        throw new Error('fakeAppIdHash should be 32 bytes!');
      }
      fakeAppIdHash.copy(testInputs.parsedAttestation.authData);
      expect(await checkRPIdPerStep6(testInputs)).toEqual('fail_rpId_mismatch');
    });
  });

  describe('computeAndCheckNoncePerStep2To4', () => {
    test('passes if nonce computed from challenge matches extension value', async () => {
      expect(await computeAndCheckNoncePerStep2To4(testInputs)).toEqual('pass');
    });

    test('fails if nonce computed from challenge does not match extension value', async () => {
      testInputs.challenge = parseUUIDV4(randomUUID());
      expect(await computeAndCheckNoncePerStep2To4(testInputs)).toEqual(
        'fail_nonce_mismatch',
      );
    });

    test('fails if nonce extension not found', async () => {
      setNonceExtensionOID('1.2.3.4.5');
      expect(await computeAndCheckNoncePerStep2To4(testInputs)).toEqual(
        'fail_nonce_missing',
      );
    });
  });

  describe('checkCertificatesPerStep1', () => {
    test('pass if cert chain can be verified', async () => {
      expect(await checkCertificatesPerStep1(testInputs)).toEqual('pass');
    });

    test('fails if cred cert cannot be verified', async () => {
      testInputs.parsedAttestation.intermediateCert = WEBAUTHN_ROOT_CERT;
      expect(await checkCertificatesPerStep1(testInputs)).toEqual(
        'fail_credCert_verify_failure',
      );
    });

    test('fails if intermediate cert cannot be verified', async () => {
      setAppAttestRootCertificate(WEBAUTHN_ROOT_CERT_PEM);
      expect(await checkCertificatesPerStep1(testInputs)).toEqual(
        'fail_intermediateCert_verify_failure',
      );
      setAppAttestRootCertificate(null);
    });
  });
});
