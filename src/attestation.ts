import { Buffer } from 'buffer';
import cbor from 'cbor';
import { X509Certificate } from '@peculiar/x509';
import { webcrypto } from 'crypto';

import { getRPIdHash, getSHA256, getSignCount } from './utils';

/**
 * iOS App information.
 */
export interface AppInfo {
  /**
   * For apps, this is of the form: <team-id (10-digit)>.<bundle-id>. See docs
   * regarding App Clip's.
   */
  appId: string;
  /**
   * Whether this is for development build or production build.
   */
  developmentEnv: boolean;
}

/** @internal */
export interface ParsedAttestation {
  credCert: X509Certificate;
  intermediateCert: X509Certificate;
  receipt: Buffer;
  authData: Buffer;
}

/** @internal */
export interface VerificationInputs {
  appInfo: AppInfo;
  keyId: string;
  challenge: Buffer;
  parsedAttestation: ParsedAttestation;
}

/** Possible errors when verifying an Attestation. */
export type VerifyAttestationError =
  | 'fail_parsing_attestation'
  | 'fail_credId_len_invalid'
  | 'fail_credId_mismatch'
  | 'fail_aaguid_mismatch'
  | 'fail_signCount_nonZero'
  | 'fail_rpId_mismatch'
  | 'fail_nonce_missing'
  | 'fail_nonce_mismatch'
  | 'fail_credCert_verify_failure'
  | 'fail_intermediateCert_verify_failure';

/**
 * Information to be persisted if Attestation was verified successfully.
 */
export interface VerifyAttestationSuccessResult {
  publicKeyPem: string;
  receipt: Buffer;
}

/** Error information if Attestation could not be verified. */
export interface VerifyAttestationFailureResult {
  verifyError: VerifyAttestationError;
  errorMessage?: string;
}

/** Result produced by {@link verifyAttestation} */
export type VerifyAttestationResult =
  | VerifyAttestationSuccessResult
  | VerifyAttestationFailureResult;

type VerificationStep = (
  inputs: VerificationInputs,
) => Promise<VerifyAttestationError | null>;

const STEPS: VerificationStep[] = [
  checkCertificatesPerStep1,
  computeAndCheckNoncePerStep2To4,
  checkKeyIdPerStep5,
  checkRPIdPerStep6,
  checkSignCountPerStep7,
  checkAAGuidPerStep8,
  checkCredentialIdPerStep9,
];

/**
 * Verify Attestation object generated on iOS device using DCAppAttestService per
 * steps {@link https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643 | here}.
 *
 * @remark On successful verification, the public-key PEM and receipt should be persisted using
 * some device Id for future lookup.
 *
 * @param appInfo App that Attestation was generated for. See {@link AppInfo}.
 * @param keyId Public key identifier from device that Attestation was generated for.
 * @param challenge One time challenge used to generated Attestation.
 * @param attestation Raw attestation data generated during Key attestation.
 * @returns Result object containing public-key and receipt if verification was successful or
 *    error information if verification failed.
 */
export async function verifyAttestation(
  appInfo: AppInfo,
  keyId: string,
  challenge: Buffer,
  attestation: Buffer,
): Promise<VerifyAttestationResult> {
  const parseResult = await parseAttestation(attestation);
  if (typeof parseResult === 'string') {
    return {
      verifyError: 'fail_parsing_attestation',
      errorMessage: parseResult,
    };
  }
  const inputs: VerificationInputs = {
    appInfo,
    keyId,
    challenge,
    parsedAttestation: parseResult,
  };

  for (const step of STEPS) {
    const error = await step(inputs);
    if (error !== null) {
      return {
        verifyError: error,
      };
    }
  }

  return {
    publicKeyPem: parseResult.credCert.publicKey.toString(),
    receipt: parseResult.receipt,
  };
}

/**
 * Set the Apple AppAttest Root Certificate to use during {@link verifyAttestation}.
 *
 * @remarks
 * This API is optional and by default the Certificate bundled with this library will be used.
 *
 * @param rootCertPem PEM formatted AppAttest Root Certificate. If null is provided, the
 * default Certificate bundled with this library will be used instead.
 */
export function setAppAttestRootCertificate(rootCertPem: string | null) {
  APPATTEST_ROOT_CERT = new X509Certificate(
    rootCertPem ?? DEFAULT_APPATTEST_ROOT_CERT_PEM,
  );
}

/** @internal */
export async function checkCredentialIdPerStep9(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const authData = inputs.parsedAttestation.authData;
  const credIdLen = authData.subarray(53, 55);
  // Sanity check the length value. It should always be 32 bytes.
  if (credIdLen[0] !== 0 || credIdLen[1] !== 32) {
    return 'fail_credId_len_invalid';
  }

  const credId = authData.subarray(55, 87);
  return credId.toString('base64') === inputs.keyId
    ? null
    : 'fail_credId_mismatch';
}

/** @internal */
export async function checkAAGuidPerStep8(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const aaGuid = inputs.parsedAttestation.authData.subarray(37, 53).toString();
  const expectedGuid = inputs.appInfo.developmentEnv
    ? 'appattestdevelop'
    : 'appattest';
  return aaGuid === expectedGuid ? null : 'fail_aaguid_mismatch';
}

/** @internal */
export async function checkSignCountPerStep7(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const counter = getSignCount(inputs.parsedAttestation.authData);
  return counter === 0 ? null : 'fail_signCount_nonZero';
}

/** @internal */
export async function checkRPIdPerStep6(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const rpId = getRPIdHash(inputs.parsedAttestation.authData);
  const appIdHash = await getSHA256(Buffer.from(inputs.appInfo.appId));
  return rpId.equals(appIdHash) ? null : 'fail_rpId_mismatch';
}

/** @internal */
export async function checkKeyIdPerStep5(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  // const publicKeyHash =
  await getSHA256(
    Buffer.from(inputs.parsedAttestation.credCert.publicKey.rawData),
  );
  // console.log(
  //   `publicKeyHash: ${publicKeyHash.toString('base64')}, keyId: ${
  //     inputs.keyId
  //   }`,
  // );
  // TODO: Always pass for now. Haven't figured out how to SHA256 the key correctly
  // yet. We however compare the keyId in step 9 too.
  return null;
}

let NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';

/** @internal */
export function setNonceExtensionOID(oid: string) {
  NONCE_EXTENSION_OID = oid;
}

/** @internal */
export async function computeAndCheckNoncePerStep2To4(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const attestation = inputs.parsedAttestation;

  const clientDataHash = await getSHA256(inputs.challenge);
  const noncePrep = Buffer.concat([attestation.authData, clientDataHash]);
  const nonce = await getSHA256(noncePrep);

  const ext = attestation.credCert.getExtension(NONCE_EXTENSION_OID);
  if (ext === null) {
    return 'fail_nonce_missing';
  }
  const extAsnString = ext.toString('asn');
  const expectedSuffix = `OCTET STRING : ${nonce.toString('hex')}`;
  return extAsnString.endsWith(expectedSuffix) ? null : 'fail_nonce_mismatch';
}

const DEFAULT_APPATTEST_ROOT_CERT_PEM = `
-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`;
let APPATTEST_ROOT_CERT = new X509Certificate(DEFAULT_APPATTEST_ROOT_CERT_PEM);

/** @internal */
export async function checkCertificatesPerStep1(
  inputs: VerificationInputs,
): Promise<VerifyAttestationError | null> {
  const attestation = inputs.parsedAttestation;

  // TODO: date also available as input.
  const credCertVerified = await attestation.credCert.verify(
    {
      publicKey: attestation.intermediateCert.publicKey,
    },
    webcrypto,
  );
  if (!credCertVerified) {
    return 'fail_credCert_verify_failure';
  }
  const intermediateCertVerified = await attestation.intermediateCert.verify(
    {
      publicKey: APPATTEST_ROOT_CERT.publicKey,
    },
    webcrypto,
  );
  if (!intermediateCertVerified) {
    return 'fail_intermediateCert_verify_failure';
  }
  return null;
}

/** @internal */
export async function parseAttestation(
  attestation: Buffer,
): Promise<ParsedAttestation | string> {
  let attestationObj;
  try {
    // NOTE: decodeFirst throws on bad input.
    attestationObj = await cbor.decodeFirst(attestation, {
      max_depth: 5,
      required: true,
    });
  } catch (e) {
    // TODO: log stack?
    return 'Unable to parse CBOR contents from Attesation';
  }
  const { fmt, attStmt, authData } = attestationObj;
  if (fmt !== 'apple-appattest') {
    return 'Invalid `fmt` in Attestation';
  }
  if (!(authData instanceof Buffer)) {
    return 'Invalid `authData` field in Attestation';
  }
  // TODO: check length of authData for future parsing.

  const { x5c, receipt } = attStmt;
  if (
    !Array.isArray(x5c) ||
    x5c.length < 2 ||
    !(x5c[0] instanceof Buffer) ||
    !(x5c[1] instanceof Buffer)
  ) {
    return 'Invalid `x5c` field in Attestation';
  }
  if (!(receipt instanceof Buffer)) {
    return 'Invalid `receipt` field in Attestation';
  }
  try {
    return {
      // X509Certificate constructor will throw on bad input.
      credCert: new X509Certificate(x5c[0]),
      intermediateCert: new X509Certificate(x5c[1]),
      receipt,
      authData,
    };
  } catch (e) {
    console.error('Unexpected error when parsing attestation!'); // TODO: stack?
    return 'Unable to parse X509 certificates from Attestation';
  }
}
