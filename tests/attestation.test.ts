import { Buffer } from 'buffer';
import cbor from 'cbor';
import { randomUUID } from 'crypto';

import {
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
  checkKeyIdPerStep5,
} from '../src/attestation';
import { getSHA256, parseUUIDV4 } from '../src/utils';
import {
  ATTESTATION_BASE64,
  KEY_ATTESTATION_CHALLENGE_STR,
  TEST_APP_INFO,
  KEY_ID,
  EXPECTED_PUBLIC_KEY_PEM,
  EXPECTED_RECEIPT_BASE64,
  WEBAUTHN_ROOT_CERT,
  WEBAUTHN_ROOT_CERT_PEM,
} from './testData';

describe('verifyAttestation', () => {
  const rawAttestation = Buffer.from(ATTESTATION_BASE64, 'base64');
  const rawServerChallenge = parseUUIDV4(KEY_ATTESTATION_CHALLENGE_STR);

  test('passes with valid input', async () => {
    const result = await verifyAttestation(
      TEST_APP_INFO,
      KEY_ID,
      rawServerChallenge,
      rawAttestation,
    );
    // Uncomment to dump values to add in testData.
    // if (!('verifyError' in result)) {
    //   console.log(`publicKeyPem: ${result.publicKeyPem}`);
    //   console.log(`receiptBase64: ${result.receipt.toString('base64')}`);
    // }
    expect(result).toEqual({
      publicKeyPem: EXPECTED_PUBLIC_KEY_PEM,
      receipt: Buffer.from(EXPECTED_RECEIPT_BASE64, 'base64'),
    });
  });

  test('fails if attestation cannot be parsed', async () => {
    expect(
      await verifyAttestation(
        TEST_APP_INFO,
        KEY_ID,
        parseUUIDV4(randomUUID()),
        Buffer.from('junk attestation data'),
      ),
    ).toEqual({
      verifyError: 'fail_parsing_attestation',
      errorMessage: 'Unable to parse CBOR contents from Attesation',
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
      verifyError: 'fail_nonce_mismatch',
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
      verifyError: 'fail_rpId_mismatch',
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
      verifyError: 'fail_keyId_mismatch',
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
      appInfo: { ...TEST_APP_INFO },
      keyId: KEY_ID,
      challenge: parseUUIDV4(KEY_ATTESTATION_CHALLENGE_STR),
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
      expect(await checkCredentialIdPerStep9(testInputs)).toBeNull();
    });

    test('fails with credId mismatch', async () => {
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
      expect(await checkAAGuidPerStep8(testInputs)).toBeNull();
    });

    test('passes if prod App Attest guid is expected', async () => {
      updateAAGuidForProd();
      testInputs.appInfo.developmentEnv = false;
      expect(await checkAAGuidPerStep8(testInputs)).toEqual(
        'fail_aaguid_mismatch',
      );
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
      expect(await checkSignCountPerStep7(testInputs)).toBeNull();
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
      expect(await checkRPIdPerStep6(testInputs)).toBeNull();
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

  describe('checkKeyIdPerStep5', () => {
    test('passes if keyId matches sha256 of public key params', async () => {
      expect(await checkKeyIdPerStep5(testInputs)).toBeNull();
    });

    test('fails if keyId computed from public key params does not match', async () => {
      testInputs.parsedAttestation.credCert = WEBAUTHN_ROOT_CERT;
      expect(await checkKeyIdPerStep5(testInputs)).toEqual(
        'fail_keyId_mismatch',
      );
    });
  });

  describe('computeAndCheckNoncePerStep2To4', () => {
    test('passes if nonce computed from challenge matches extension value', async () => {
      expect(await computeAndCheckNoncePerStep2To4(testInputs)).toBeNull();
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
      expect(await checkCertificatesPerStep1(testInputs)).toBeNull();
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

describe('parseAttestation', () => {
  const CASES: [unknown, string][] = [
    // fmt field missing.
    [{}, 'Invalid `fmt` in Attestation'],
    // fmt does not match
    [{ fmt: 'random' }, 'Invalid `fmt` in Attestation'],
    // attStmt missing.
    [{ fmt: 'apple-appattest' }, 'Invalid `attStmt` in Attestation'],
    // attStmt is not object.
    [
      { fmt: 'apple-appattest', attStmt: 'junk' },
      'Invalid `attStmt` in Attestation',
    ],
    // authData missing.
    [
      { fmt: 'apple-appattest', attStmt: {} },
      'Invalid `authData` in Attestation',
    ],
    // authData is not Buffer.
    [
      { fmt: 'apple-appattest', attStmt: {}, authData: 'junk' },
      'Invalid `authData` in Attestation',
    ],
    // authData is not long enough.
    [
      { fmt: 'apple-appattest', attStmt: {}, authData: Buffer.alloc(87) },
      'authData has < 88 bytes',
    ],
    // Missing x5c.
    [
      { fmt: 'apple-appattest', authData: Buffer.alloc(88), attStmt: {} },
      'Invalid `x5c` field in Attestation',
    ],
    // Invalid x5c, not array
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: { x5c: 'junk' },
      },
      'Invalid `x5c` field in Attestation',
    ],
    // Invalid x5c, not array of Buffers.
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: { x5c: ['invalid', 'array'] },
      },
      'Invalid `x5c` field in Attestation',
    ],
    // Invalid x5c, only single Buffer.
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: { x5c: [Buffer.alloc(25)] },
      },
      'Invalid `x5c` field in Attestation',
    ],
    // Missing receipt
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: { x5c: [Buffer.alloc(25), Buffer.alloc(25)] },
      },
      'Invalid `receipt` field in Attestation',
    ],
    // Invalid receipt type
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: { x5c: [Buffer.alloc(25), Buffer.alloc(25)], receipt: 'junk' },
      },
      'Invalid `receipt` field in Attestation',
    ],
    // Cannot parse first x5c
    [
      {
        fmt: 'apple-appattest',
        authData: Buffer.alloc(88),
        attStmt: {
          x5c: [Buffer.alloc(25), Buffer.alloc(25)],
          receipt: Buffer.alloc(8),
        },
      },
      'Unable to parse X509 certificates from Attestation',
    ],
  ];

  test.each(CASES)(
    'Fails on %p with error: %p',
    async (attestationObj, expectedError) => {
      expect(await parseAttestation(cbor.encode(attestationObj))).toEqual(
        expectedError,
      );
    },
  );
});
