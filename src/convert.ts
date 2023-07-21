import { IIdentifier, IKey, TKeyType } from '@veramo/core';
import { IAccountIn, IKeyPairBytes } from '@ltonetwork/lto/interfaces';
import { Account, Binary } from '@ltonetwork/lto';

export function ofKey({ meta, type, privateKeyHex, publicKeyHex }: IKey): IAccountIn {
  return {
    ...meta,
    keyType: type.toLowerCase(),
    privateKey: privateKeyHex ? Binary.fromHex(privateKeyHex) : undefined,
    publicKey: Binary.fromHex(publicKeyHex),
  };
}

function getManagementKey(identifier: IIdentifier): IKey & { privateKeyHex: string } {
  const controllerKeyId = identifier.controllerKeyId ?? `${identifier.did}#sign`;
  const managementKey = identifier.keys.find((key) => key.kid === controllerKeyId);

  if (!managementKey) throw new Error(`No management key found for ${identifier.did}`);
  if (!managementKey.privateKeyHex) throw new Error(`Private key not known for ${identifier.did}`);

  return managementKey as IKey & { privateKeyHex: string };
}

export function ofIdentifier(identifier: IIdentifier): IAccountIn {
  const managementKey = getManagementKey(identifier);
  return ofKey(managementKey);
}

export function accountAsKey(account: Account, { kms, type }: { kms?: string; type?: 'sign' | 'encrypt' }): IKey {
  type ??= 'sign';
  let keyType: TKeyType;
  let keyPair: IKeyPairBytes;

  if (type === 'encrypt') {
    if (account.keyType !== 'ed25519') throw new Error('Only ed25519 accounts have an encryption key');
    keyType = 'X25519';
    keyPair = account.encryptKey;
  } else {
    keyType = (account.keyType.charAt(0).toUpperCase() + account.keyType.slice(1)) as TKeyType;
    keyPair = account.signKey;
  }

  return {
    kid: `${account.did}#${type}`,
    kms: kms || 'kms',
    privateKeyHex: keyPair.privateKey?.hex,
    publicKeyHex: keyPair.publicKey.hex,
    type: keyType,
    meta: {
      address: account.address,
      seed: account.seed,
      nonce: account.nonce instanceof Binary ? `base64:${account.nonce.base64}` : account.nonce,
    },
  };
}
