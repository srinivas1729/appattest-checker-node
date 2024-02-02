# Apple AppAttest Checker for Node.js

_app-attest-checker_ is a [Node.js](https://en.wikipedia.org/wiki/Node.js) library to check
Attestation and Assertion objects generated on iOS devices. It can be used in your Node.js
based server to cryptographically check that requests received in your backend are from
legitimate versions of your app, running on actual iOS devices.

Background:

1. See these [docs](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity)
   on how your iOS app needs to generate a public/private key-pair and get them certified by
   Apple. Certification will produce an _Attestation_ object that should be sent your server for
   verification. This library includes an API to parse & verify the Attestation and retrieve the
   public-key for the device from it. Your server should store this public-key indexed by the
   device-id.

1. Later when your app needs to make normal server requests, it can sign the request contents with
   with the private-key on the device to produce an _Assertion_. The Assertion should be sent along
   with the request to the backend (e.g. in a HTTP header). The server can verify that the request
   came from a a legitimate app/device using another API from this library to check the Assertion.

This library verifies Attestations and Assertions per steps provided in App Attest [docs](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server).

## Consuming the library

The library is avaible on [NPM](www.npmjs.com/package/appattest-checker-node).

```
npm install appattest-checker-node
```

## Library usage

### Verifying Attestation

Use the `verifyAttestation` API to check the Attestation produced by `DCAppAttestService.attestKey`
API on the device ([reference](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity#3561588)).
The `challenge` should be the random value provided by the server to the client to generate the
Attestation. `keyId` is the identifier of the public key generated on the device.

```
  const result = await verifyAttestation(
    {
      appId: '<team-id>.<bundle-id>',
      develomentEnv: false,
    },  // appInfo
    keyId,
    challenge,
    attestation
  );
  if ('verifyError' in result) {
    // Return error to app.
    // It should not use the generated keys for assertion.
  } else {
    // Save publicKey and receipt for this device (sample code).
    db.save(deviceId, result.publicKeyPem, result.receipt, 0 /* signCount */);

    // Return success to app.
    // It can use the generated keys for request assertion.
  }

```

#### Certificate verification

The Attestation includes X509 certificates (`credCert` and `intermediateCert`) and part of the
verification involves checking that they were issued by Apple. The library uses a copy of Apple's
App Attest Certificate (from [here](https://www.apple.com/certificateauthority/private/)) for this.
If you want to specify a custom Root certificate to use (e.g. because the library's copy is stale),
use the following API before invoking `verifyAttestation`:

```
  setAppAttestRootCertificate(CUSTOM_ROOT_CERTIFICATE_IN_PEM_FORMAT);
```

### Verifying Assertions

Use the `verifyAssertion` API to check Assertions produced by the
`DCAppAttestService.generateAssertion` on the device ([reference](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity#3561591)).
The app should include Assertions for all important / high value requests (e.g. in a header). If a
high value request is missing an Assertion, the server should fail the request. Also if an
Assertion is present, the server should verify it as shown below or fail the request.

```
  const clientDataHash = // SHA-256 of request contents including challenge provided to client.

  // Check that challenge in request matches challenge issued by server
  // If there is mismatch, fail the request!

  // Lookup public key for the device (sample code).
  const record = db.load(deviceId);

  const result = await verifyAssertion(
    clientDataHash,
    record.publicKeyPem,
    '<team-id>.<bundle-id>',  // appId
    assertion
  );
  if ('verifyError' in result) {
    // Request cannot be trusted!
    // Fail request from app (e.g. return HTTP 401 equivalent)
  }

  // Check that signCount > persisted value and update.
  if (result.signCount <= record.signCount) {
    // Request cannot be trusted!
    // Fail request from app (e.g. return HTTP 401 equivalent)
  }
  db.update(deviceId, result.signCount);

  // Otherwise request can be trusted and continue processing as usual.
```

Ensure that `clientDataHash` is computed consistently in the app and server. In particular, before
computing SHA256 of the request body, the body needs to be consistent in the client and server.
Any syntatic differences in the request body (e.g. different ordering of fields) can produce
different hashes. Use utilities like [`json-stable-stringify`](https://www.npmjs.com/package/json-stable-stringify)
to produce consistent orderings and hashes.
