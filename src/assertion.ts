import { Buffer } from 'buffer';
import { createPublicKey, createVerify } from 'crypto';
import cbor from 'cbor';
import { getRPIdHash, getSHA256, getSignCount } from './utils';

/** Possible errors when verifying an Assertion. */
export type VerifyAssertionError =
  | 'fail_parsing_assertion'
  | 'fail_rpId_mismatch'
  | 'fail_invalid_publicKey'
  | 'fail_signature_verification';

/**
 * Result when Assertion is verified successfully.
 */
export interface VerifyAssertionSuccessResult {
  signCount: number;
}

/**
 * Result when Assertion cannot be verified.
 */
export interface VerifyAssertionFailureResult {
  verifyError: VerifyAssertionError;
  errorMessage?: string;
}

type VerifyAssertionResult =
  | VerifyAssertionSuccessResult
  | VerifyAssertionFailureResult;

/** @internal */
export interface ParsedAssertion {
  signature: Buffer;
  authData: Buffer;
}

/** @internal */
export interface VerifyAssertionInputs {
  clientDataHash: Buffer;
  publicKeyPem: string;
  appId: string;
  parsedAssertion: ParsedAssertion;
}

type VerificationStep = (
  inputs: VerifyAssertionInputs,
) => Promise<VerifyAssertionError | null>;

const STEPS: VerificationStep[] = [
  verifySignaturePerStep1To3,
  verifyRPIdPerStep4,
];

/**
 * Verify an Assertion generated on an iOS device using DCAppAttestService per steps 1-4
 * {@link https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644 | here}.
 *
 * @remark This code does not verify that any challenge inluded in clientDataHash is valid. Calling
 * code should do that. Also, on successful verification, the signCount from the Assertion is
 * returned. Calling code should check that it exceeds any previous persisted signCount and persist
 * the returned value. These two points are mentioned in Steps 5 & 6 from steps above.
 *
 * @remark Ensure that clientDataHash is computed from the same request that was used by the client
 * for assertion. Any formatting changes could result in issues.
 *
 * @param clientDataHash SHA256 of the client data (request).
 * @param publicKeyPem Public Key of the key pair from the device.
 * @param appId App Id that generated the assertion.
 * @param assertion Assertion bytes sent up from the device; derived on device by signing
 *    clientDataHash with private key on the device.
 * @returns Result object containing signCount if assertion was verified or error if it was not
 *    verified.
 */
export async function verifyAssertion(
  clientDataHash: Buffer,
  publicKeyPem: string,
  appId: string,
  assertion: Buffer,
): Promise<VerifyAssertionResult> {
  const parseResult = await parseAssertion(assertion);
  if (typeof parseResult === 'string') {
    return { verifyError: 'fail_parsing_assertion', errorMessage: parseResult };
  }

  const inputs = {
    clientDataHash,
    publicKeyPem,
    appId,
    parsedAssertion: parseResult,
  };

  for (const step of STEPS) {
    const error = await step(inputs);
    if (error != null) {
      return {
        verifyError: error,
      };
    }
  }

  return {
    signCount: getSignCount(inputs.parsedAssertion.authData),
  };
}

/** @internal */
export async function verifyRPIdPerStep4(
  inputs: VerifyAssertionInputs,
): Promise<VerifyAssertionError | null> {
  const rpIdHash = getRPIdHash(inputs.parsedAssertion.authData);
  const appIdHash = await getSHA256(Buffer.from(inputs.appId));
  return rpIdHash.equals(appIdHash) ? null : 'fail_rpId_mismatch';
}

/** @internal */
export async function verifySignaturePerStep1To3(
  inputs: VerifyAssertionInputs,
): Promise<VerifyAssertionError | null> {
  const noncePrep = Buffer.concat([
    inputs.parsedAssertion.authData,
    inputs.clientDataHash,
  ]);
  const nonce = await getSHA256(noncePrep);

  let publicKey;
  try {
    publicKey = createPublicKey(inputs.publicKeyPem);
  } catch (e) {
    return 'fail_invalid_publicKey';
  }
  const verifier = createVerify('RSA-SHA256');
  verifier.update(nonce);
  const verified = verifier.verify(publicKey, inputs.parsedAssertion.signature);
  return verified ? null : 'fail_signature_verification';
}

/** @internal */
export async function parseAssertion(
  assertion: Buffer,
): Promise<ParsedAssertion | string> {
  try {
    const assertionObj = await cbor.decodeFirst(assertion);
    const { signature, authenticatorData } = assertionObj;
    if (!(signature instanceof Buffer)) {
      return 'Invalid `signature` field in Assertion';
    }
    if (!(authenticatorData instanceof Buffer)) {
      return 'Invalid `authenticatorData` field in Assertion';
    }
    // TODO: check authenticatorData bytelength.
    return {
      signature,
      authData: authenticatorData,
    };
  } catch (e) {
    return 'Unable to parse CBOR contents from Assertion';
  }
}
