import stringify from 'json-stable-stringify';

import {
  VerifyAssertionInputs,
  parseAssertion,
  verifyAssertion,
  verifyRPIdPerStep4,
  verifySignaturePerStep1To3,
} from '../src/assertion';

import {
  TEST_APP_INFO,
  REQUEST,
  REQUEST_ASSERTION_BASE64,
  EXPECTED_PUBLIC_KEY_PEM,
} from './testData';
import { getSHA256 } from '../src/utils';

describe('verifyAssertion', () => {
  let clientDataHash: Buffer;
  let requestAssertion: Buffer;

  beforeEach(async () => {
    clientDataHash = await getSHA256(Buffer.from(stringify(REQUEST)));
    requestAssertion = Buffer.from(REQUEST_ASSERTION_BASE64, 'base64');
  });

  test('passes with valid inputs', async () => {
    const verifyResult = await verifyAssertion(
      clientDataHash,
      EXPECTED_PUBLIC_KEY_PEM,
      TEST_APP_INFO.appId,
      requestAssertion,
    );
    expect(verifyResult).toEqual({ signCount: 1 });
  });

  test('fails and returns error if any step fails', async () => {
    const verifyResult = await verifyAssertion(
      clientDataHash,
      EXPECTED_PUBLIC_KEY_PEM,
      'junk_app_id',
      requestAssertion,
    );
    expect(verifyResult).toEqual({ verifyError: 'fail_rpId_mismatch' });
  });
});

describe('VerificationStep tests', () => {
  let clientDataHash: Buffer;
  let requestAssertion: Buffer;
  let inputs: VerifyAssertionInputs;

  beforeEach(async () => {
    clientDataHash = await getSHA256(Buffer.from(stringify(REQUEST)));
    requestAssertion = Buffer.from(REQUEST_ASSERTION_BASE64, 'base64');
    const parseResult = await parseAssertion(requestAssertion);
    if (typeof parseResult === 'string') {
      throw new Error('ParsedAssertion expected!');
    }
    inputs = {
      clientDataHash,
      publicKeyPem: EXPECTED_PUBLIC_KEY_PEM,
      appId: TEST_APP_INFO.appId,
      parsedAssertion: parseResult,
    };
  });

  describe('verifyRPIdPerStep4', () => {
    test('passes if SHA256 of appId matches RP Id', async () => {
      expect(await verifyRPIdPerStep4(inputs)).toBeNull();
    });

    test('fails if SHA256 of appId matches RP Id', async () => {
      inputs.appId = 'randomAppId';
      expect(await verifyRPIdPerStep4(inputs)).toEqual('fail_rpId_mismatch');
    });
  });

  describe('verifySignaturePerStep1To3', () => {
    test('passes if signature can be verified using publicKey', async () => {
      expect(await verifySignaturePerStep1To3(inputs)).toBeNull();
    });

    test('fails if publicKey cannot be parsed', async () => {
      inputs.publicKeyPem = 'junk_key_content';
      expect(await verifySignaturePerStep1To3(inputs)).toEqual(
        'fail_invalid_publicKey',
      );
    });

    test('fails if signature does not match', async () => {
      inputs.clientDataHash = await getSHA256(
        Buffer.from('junk_request_content'),
      );
      expect(await verifySignaturePerStep1To3(inputs)).toEqual(
        'fail_signature_verification',
      );
    });
  });
});
