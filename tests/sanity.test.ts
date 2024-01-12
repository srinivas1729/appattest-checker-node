import * as x509 from '@peculiar/x509';
import { Buffer } from 'buffer';
import cbor from 'cbor';

test.skip('x509 failure', () => {
  new x509.X509Certificate(Buffer.from('hello world', 'utf8'));
  ``;
});

test.skip('cbor failure', async () => {
  await cbor.decodeFirst(Buffer.from('hello', 'utf8'));
});
