import stringify from 'json-stable-stringify';

import { verifyAssertion } from '../src/assertion';

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

  test.only('passes with valid inputs', async () => {
    const verifyResult = await verifyAssertion(
      clientDataHash,
      EXPECTED_PUBLIC_KEY_PEM,
      TEST_APP_INFO.appId,
      requestAssertion,
    );
    expect(verifyResult).toEqual({ signCount: 1 });
  });
});
