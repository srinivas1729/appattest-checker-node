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

export function getRPIdHash(authData: Buffer): Buffer {
  return authData.subarray(0, 32);
}

export function getSignCount(authData: Buffer): number {
  return authData.readInt32BE(33);
}
