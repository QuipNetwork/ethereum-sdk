import { ethers } from 'ethers';
import { WOTSPlus } from '../../hashsigs-ts/dist/wotsplus.js';

async function main() {
  if (process.argv.length < 7) {
    console.error('Usage: ts-node debugTransfer.ts <quantum_secret> <vault_id> <public_seed> <to_address> <amount>');
    process.exit(1);
  }
  const quantum_secret = process.argv[2];
  const vault_id = process.argv[3];
  const public_seed_str = process.argv[4];
  const to_address = process.argv[5];
  const amount = process.argv[6];

  console.log('quantum_secret:', quantum_secret);
  console.log('vault_id:', vault_id);

  const concat = Buffer.concat([
    Buffer.from(quantum_secret.slice(2), 'hex'),
    Buffer.from(vault_id.slice(2), 'hex'),
  ]);
  console.log('concat (quantum_secret || vault_id): 0x' + concat.toString('hex'));
  const private_seed = Buffer.from(ethers.keccak256(concat).slice(2), 'hex');

  console.log('private_seed:', '0x' + Buffer.from(private_seed).toString('hex'));
  const wots = new WOTSPlus((data: Uint8Array) => ethers.getBytes(ethers.keccak256(data)));
  const public_seed = Buffer.from(public_seed_str.slice(2), 'hex');
  console.log('public_seed:', '0x' + Buffer.from(public_seed).toString('hex'));
  const { publicKey, privateKey } = wots.generateKeyPair(private_seed, public_seed);

  console.log("current_pq_address.publicSeed: 0x" + Buffer.from(publicKey).toString('hex').slice(0, 64));
  console.log("current_pq_address.publicKeyHash: 0x" + Buffer.from(publicKey).toString('hex').slice(64));

  // Generate randomization elements for debug
  function prf(seed: Uint8Array, index: number): Uint8Array {
    const buffer = new Uint8Array(1 + seed.length + 2);
    buffer[0] = 0x03;
    buffer.set(seed, 1);
    buffer[seed.length + 1] = (index >> 8) & 0xFF;
    buffer[seed.length + 2] = index & 0xFF;
    return ethers.getBytes(ethers.keccak256(buffer));
  }
  function hash(data: Uint8Array): Uint8Array {
    return ethers.getBytes(ethers.keccak256(data));
  }
  const randomizationElements = [];
  for (let i = 0; i < wots.numSignatureChunks; i++) {
    randomizationElements.push(prf(public_seed, i));
  }
  // Print privateKey
  console.log('privateKey:', '0x' + Buffer.from(privateKey).toString('hex'));
  // Print functionKey
  console.log('functionKey:', '0x' + Buffer.from(randomizationElements[0]).toString('hex'));
  // Print first secretKeySegment (i=0)
  const prf0 = prf(privateKey, 1);
  const concat0 = new Uint8Array([...randomizationElements[0], ...prf0]);
  const secretKeySegment0 = hash(concat0);
  console.log('secretKeySegment[0]:', '0x' + Buffer.from(secretKeySegment0).toString('hex'));

  // Next key
  const next_public_seed = Buffer.alloc(32, 0); // 32 bytes of zeros for deterministic test
  console.log('next_public_seed:', '0x' + next_public_seed.toString('hex'));
  const { publicKey: next_publicKey, privateKey: next_privateKey } = wots.generateKeyPair(private_seed, next_public_seed);
  console.log('next_pq_address.publicSeed: 0x' + Buffer.from(next_publicKey).toString('hex').slice(0, 64));
  console.log('next_pq_address.publicKeyHash: 0x' + Buffer.from(next_publicKey).toString('hex').slice(64));

  // Helper to slice a hex string (with 0x prefix) by byte offset
  function hexSlice(hex: string, start: number, end: number) {
    return '0x' + hex.slice(2 + start * 2, 2 + end * 2);
  }
  const publicKeyHex = '0x' + Buffer.from(publicKey).toString('hex');
  const nextPublicKeyHex = '0x' + Buffer.from(next_publicKey).toString('hex');

  const packed = ethers.solidityPacked([
    'bytes32', 'bytes32', 'bytes32', 'bytes32', 'address', 'uint256'
  ], [
    hexSlice(publicKeyHex, 0, 32),
    hexSlice(publicKeyHex, 32, 64),
    hexSlice(nextPublicKeyHex, 0, 32),
    hexSlice(nextPublicKeyHex, 32, 64),
    to_address,
    amount
  ]);
  console.log('packed_message_data: ' + packed);

  // Hash message data
  const message_hash = ethers.keccak256(ethers.getBytes(packed));
  console.log('message_hash:', message_hash);
  const message_hash_bytes = ethers.getBytes(message_hash);
  console.log('message_hash_bytes.length:', message_hash_bytes.length);
  console.log('message_hash_bytes.constructor.name:', message_hash_bytes.constructor.name);

  // Sign
  const sig = wots.sign(message_hash_bytes, privateKey, public_seed);
  let sigHex: string;
  if (Array.isArray(sig)) {
    sigHex = Buffer.concat(sig.map((x: Uint8Array) => Buffer.from(x))).toString('hex');
  } else {
    sigHex = Buffer.from(sig as Uint8Array).toString('hex');
  }
  console.log('signature: 0x' + sigHex);

  console.log('DEBUG types:',
    typeof hexSlice(publicKeyHex, 0, 32),
    typeof hexSlice(publicKeyHex, 32, 64),
    typeof hexSlice(nextPublicKeyHex, 0, 32),
    typeof hexSlice(nextPublicKeyHex, 32, 64),
    typeof to_address,
    typeof amount
  );

  const zeros64 = Buffer.alloc(64, 0);
  const hash_zeros64 = ethers.keccak256(zeros64);
  console.log('keccak256(zeros64):', hash_zeros64);
} 

main().catch((error) => {
  console.error(error);
  process.exit(1);
}); 