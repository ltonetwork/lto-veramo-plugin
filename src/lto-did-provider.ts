import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { DIDDocument, IAgentContext, IIdentifier, IKey, IKeyManager, IService, TKeyType } from '@veramo/core';
import LTO, { Binary, Account, IdentityBuilder, Transaction } from '@ltonetwork/lto';
import { IAccountIn, ISigner, TDIDRelationship } from '@ltonetwork/lto/interfaces';

interface LtoOptions {
  defaultKms: string;
  sponsor?: ISigner | IAccountIn;
  lto?: LTO;
  networkId?: string;
  nodeAddress?: string;
  nodeApiKey?: string;
}

interface AccountOptions extends IAccountIn {
  publicKeyHex?: string;
  privateKeyHex?: string;
}

interface CreateIdentifierOptions {
  verificationMethods?: VerificationMethod[];
  services?: IService[];
}

interface RelationshipOptions {
  authentication?: boolean;
  assertionMethod?: boolean;
  keyAgreement?: boolean;
  capabilityInvocation?: boolean;
  capabilityDelegation?: boolean;
}
const ALL_RELATIONSHIPS = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityInvocation',
  'capabilityDelegation',
];

interface VerificationMethod extends AccountOptions, RelationshipOptions {
  expires?: Date;
}

export class LtoDIDProvider extends AbstractIdentifierProvider {
  readonly defaultKms: string;
  readonly lto: LTO;
  readonly sponsor?: Account;

  constructor(options: LtoOptions) {
    super();

    this.defaultKms = options.defaultKms;

    this.lto = options.lto ?? new LTO(options.networkId ?? 'T');
    if (options.lto && options.networkId && options.lto.networkId !== options.networkId) {
      throw new Error(`Network id mismatch: expected '${options.networkId}', got '${options.lto.networkId}'`);
    }

    if (options.sponsor) {
      this.sponsor = options.sponsor instanceof Account ? options.sponsor : this.lto.account(options.sponsor);
    }
  }

  private async broadcast(...tsx: Transaction[]): Promise<Transaction[]> {
    if (this.sponsor) {
      tsx.forEach((tx) => tx.sponsorWith(this.sponsor));
    }

    return Promise.all(tsx.map((tx) => this.lto.node.broadcast(tx)));
  }

  private account(options: AccountOptions): Account {
    const { publicKeyHex, privateKeyHex, ...accountOptions } = options;
    if (publicKeyHex) accountOptions.publicKey = Binary.fromHex(publicKeyHex);
    if (privateKeyHex) accountOptions.privateKey = Binary.fromHex(privateKeyHex);

    return this.lto.account(options);
  }

  private accountFromKey({ meta, type, privateKeyHex, publicKeyHex }: IKey): Account {
    return this.lto.account({
      ...meta,
      keyType: type.toLowerCase(),
      privateKey: privateKeyHex ? Binary.fromHex(privateKeyHex) : undefined,
      publicKey: Binary.fromHex(publicKeyHex),
    });
  }

  private getManagementKey(identifier: IIdentifier): IKey & { privateKeyHex: string } {
    const controllerKeyId = identifier.controllerKeyId ?? `${identifier.did}#sign`;
    const managementKey = identifier.keys.find((key) => key.kid === controllerKeyId);

    if (!managementKey) throw new Error(`No management key found for ${identifier.did}`);
    if (!managementKey.privateKeyHex) throw new Error(`Private key not known for ${identifier.did}`);

    return managementKey as IKey & { privateKeyHex: string };
  }

  private getRelationships(options: RelationshipOptions): TDIDRelationship[] {
    return Object.entries(options)
      .filter(([key, value]) => ALL_RELATIONSHIPS.includes(key) && !!value)
      .map(([key]) => key as TDIDRelationship);
  }

  private async createKey(
    context: IAgentContext<IKeyManager>,
    { kms }: { kms?: string },
    account: Account,
  ): Promise<IKey> {
    if (!account.signKey.privateKey) throw new Error('Account does not have a private key');

    const keyType = (account.keyType.charAt(0).toUpperCase() + account.keyType.slice(1)) as TKeyType;

    return await context.agent.keyManagerImport({
      kid: `${account.did}#sign`,
      kms: kms || this.defaultKms,
      privateKeyHex: account?.signKey.privateKey!.hex,
      publicKeyHex: account?.signKey.publicKey.hex,
      type: keyType,
      meta: {
        address: account.address,
        seed: account.seed,
        nonce: account.nonce instanceof Binary ? `base64:${account.nonce.base64}` : account.nonce,
      },
    });
  }

  private async createEncryptKey(
    context: IAgentContext<IKeyManager>,
    { kms }: { kms?: string },
    account: Account,
  ): Promise<IKey> {
    if (!account.encryptKey.privateKey) throw new Error('Account does not have a private encryption key');
    if (account.keyType !== 'ed25519') throw new Error('Not an X25519 encryption key');

    return await context.agent.keyManagerImport({
      kid: `${account.did}#encrypt`,
      kms: kms || this.defaultKms,
      privateKeyHex: account?.encryptKey.privateKey!.hex,
      publicKeyHex: account?.encryptKey.publicKey.hex,
      type: 'X25519',
      meta: {
        address: account.address,
        seed: account.seed,
        nonce: typeof account.nonce === 'number' ? account.nonce : account.nonce?.hex,
      },
    });
  }

  private async registerDID(
    options: AccountOptions & RelationshipOptions & CreateIdentifierOptions,
  ): Promise<IdentityBuilder> {
    const account = this.account(options);
    const builder = new IdentityBuilder(account);

    if (ALL_RELATIONSHIPS.some((key) => key in options)) {
      const relationships = this.getRelationships(options);
      if (relationships.length !== ALL_RELATIONSHIPS.length) {
        builder.addVerificationMethod(account, relationships);
      }
    }

    for (const method of options.verificationMethods ?? []) {
      builder.addVerificationMethod(this.account(method), this.getRelationships(method), method.expires);
    }

    for (const service of options.services ?? []) {
      builder.addService(service);
    }

    await this.broadcast(...builder.transactions);

    return builder;
  }

  async createIdentifier(
    args: {
      kms?: string;
      options?: AccountOptions & RelationshipOptions & CreateIdentifierOptions;
    },
    context: IAgentContext<IKeyManager>,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const builder = await this.registerDID(args.options ?? {});
    const accounts = [builder.account, ...builder.newMethods.map((method) => method.account)];

    const promises = [];
    for (const account of accounts) {
      promises.push(this.createKey(context, args, account));
      if (account.keyType === 'ed25519') promises.push(this.createEncryptKey(context, args, account));
    }
    const keys = await Promise.all(promises);

    return {
      did: builder.account.did,
      controllerKeyId: `${builder.account.did}#sign`,
      keys: keys,
      services: args.options?.services || [],
    };
  }

  async deleteIdentifier(args: IIdentifier, context: IAgentContext<IKeyManager>): Promise<boolean> {
    const managementKey = this.getManagementKey(args);
    const account = this.accountFromKey(managementKey);

    const tx = new IdentityBuilder(account).deactivate();
    await this.broadcast(tx);

    return true;
  }

  updateIdentifier(
    args: { did: string; document: Partial<DIDDocument>; options?: { [p: string]: any } },
    context: IAgentContext<IKeyManager>,
  ): Promise<IIdentifier> {
    throw new Error('LtoDIDProvider updateIdentifier not supported');
  }

  private builder(account: Account, options?: { builder?: IdentityBuilder }) {
    if (options?.builder && options?.builder?.account.address !== account.address) {
      throw new Error('Builder account does not match identifier management key');
    }

    return options?.builder ?? new IdentityBuilder(account);
  }

  async addKey(
    args: {
      identifier: IIdentifier;
      key: IKey;
      options?: RelationshipOptions & { expires?: Date; builder?: IdentityBuilder };
    },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const managementKey = this.getManagementKey(args.identifier);
    const account = this.accountFromKey(managementKey);

    const subAccount = this.accountFromKey(args.key);
    const relationships = this.getRelationships(args.options ?? {});

    const builder = this.builder(account, args.options);
    builder.addVerificationMethod(subAccount, relationships, args.options?.expires);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.broadcast(...builder.transactions);
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const managementKey = this.getManagementKey(args.identifier);
    const account = this.accountFromKey(managementKey);

    const builder = this.builder(account, args.options);
    builder.removeVerificationMethod(args.kid);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.broadcast(...builder.transactions);
  }

  async addService(
    args: { identifier: IIdentifier; service: IService; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const managementKey = this.getManagementKey(args.identifier);
    const account = this.accountFromKey(managementKey);

    const builder = this.builder(account, args.options);
    builder.addService(args.service);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.broadcast(...builder.transactions);
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const managementKey = this.getManagementKey(args.identifier);
    const account = this.accountFromKey(managementKey);

    const builder = this.builder(account, args.options);
    builder.removeService(args.id);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.broadcast(...builder.transactions);
  }
}
