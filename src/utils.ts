import { Buffer } from 'buffer';
import { createHash } from 'crypto';

export async function getSHA256(data: Buffer) {
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest();
}

export function parseUUIDV4(uuid: string): Buffer {
  return Buffer.from(uuid.split('-').join(''), 'hex');
}
