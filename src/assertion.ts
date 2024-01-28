import { Buffer } from 'buffer';
import { createPublicKey, createVerify } from 'crypto';
import cbor from 'cbor';
import { getRPIdHash, getSHA256, getSignCount } from './utils';

// TODO: more error types.
export type VerifyAssertionError = 'fail';

export interface VerifyAssertionSuccessResult {
  signCount: number;
}

export interface VerifyAssertionFailureResult {
  verifyError: VerifyAssertionError;
}

type VerifyAssertionResult =
  | VerifyAssertionSuccessResult
  | VerifyAssertionFailureResult;

export interface ParsedAssertion {
  signature: Buffer;
  authData: Buffer;
}

interface VerifyAssertionInputs {
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

export async function verifyAssertion(
  clientDataHash: Buffer,
  publicKeyPem: string,
  appId: string,
  assertion: Buffer,
): Promise<VerifyAssertionResult> {
  const parseResult = await parseAssertion(assertion);
  if (typeof parseResult === 'string') {
    return { verifyError: 'fail' };
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

export async function verifyRPIdPerStep4(
  inputs: VerifyAssertionInputs,
): Promise<VerifyAssertionError | null> {
  const rpIdHash = getRPIdHash(inputs.parsedAssertion.authData);
  const appIdHash = await getSHA256(Buffer.from(inputs.appId));
  return rpIdHash.equals(appIdHash) ? null : 'fail';
}

export async function verifySignaturePerStep1To3(
  inputs: VerifyAssertionInputs,
): Promise<VerifyAssertionError | null> {
  const noncePrep = Buffer.concat([
    inputs.parsedAssertion.authData,
    inputs.clientDataHash,
  ]);
  const nonce = await getSHA256(noncePrep);

  // TODO: error cases!
  const publicKey = createPublicKey(inputs.publicKeyPem);
  const verifier = createVerify('RSA-SHA256');
  verifier.update(nonce);
  const verified = verifier.verify(publicKey, inputs.parsedAssertion.signature);
  return verified ? null : 'fail';
}

async function parseAssertion(
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
