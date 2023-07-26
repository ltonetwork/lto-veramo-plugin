import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { DIDDocument, IAgentContext, IIdentifier, IKey, IKeyManager, IService } from '@veramo/core';
import { Account, IdentityBuilder, Transaction } from '@ltonetwork/lto';
import { TDIDRelationship } from '@ltonetwork/lto/interfaces';
import { accountAsKey, ofIdentifier, ofKey } from './convert';
import { AccountOptions, LtoConnection, LtoOptions } from './lto-connection';

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
  readonly lto: LtoConnection;
  readonly sponsor?: Account;

  constructor(options: LtoOptions & { defaultKms: string }) {
    super();

    this.defaultKms = options.defaultKms;
    this.lto = new LtoConnection(options);
  }

  private builder(account: Account, options?: { builder?: IdentityBuilder }) {
    if (options?.builder && options?.builder?.account.address !== account.address) {
      throw new Error('Builder account does not match identifier management key');
    }

    return options?.builder ?? new IdentityBuilder(account);
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

    const key = accountAsKey(account, { kms: kms || this.defaultKms }) as Required<IKey>;
    return await context.agent.keyManagerImport(key);
  }

  private async createEncryptKey(
    context: IAgentContext<IKeyManager>,
    { kms }: { kms?: string },
    account: Account,
  ): Promise<IKey> {
    if (!account.encryptKey.privateKey) throw new Error('Account does not have a private encryption key');

    const key = accountAsKey(account, { kms: kms || this.defaultKms, type: 'encrypt' }) as Required<IKey>;
    return await context.agent.keyManagerImport(key);
  }

  private async registerDID(
    options: AccountOptions & RelationshipOptions & CreateIdentifierOptions,
  ): Promise<IdentityBuilder> {
    const account = this.lto.account(options);
    const builder = new IdentityBuilder(account);

    if (ALL_RELATIONSHIPS.some((key) => key in options)) {
      const relationships = this.getRelationships(options);
      if (relationships.length !== ALL_RELATIONSHIPS.length) {
        builder.addVerificationMethod(account, relationships);
      }
    }

    for (const method of options.verificationMethods ?? []) {
      builder.addVerificationMethod(this.lto.account(method), this.getRelationships(method), method.expires);
    }

    for (const service of options.services ?? []) {
      builder.addService(service);
    }

    await this.lto.broadcast(...builder.transactions);

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
    const account = this.lto.account(ofIdentifier(args));

    const tx = new IdentityBuilder(account).deactivate();
    await this.lto.broadcast(tx);

    return true;
  }

  updateIdentifier(
    args: { did: string; document: Partial<DIDDocument>; options?: { [p: string]: any } },
    context: IAgentContext<IKeyManager>,
  ): Promise<IIdentifier> {
    throw new Error('LtoDIDProvider updateIdentifier not supported');
  }

  async addKey(
    args: {
      identifier: IIdentifier;
      key: IKey;
      options?: RelationshipOptions & { expires?: Date; builder?: IdentityBuilder };
    },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const account = this.lto.account(ofIdentifier(args.identifier));

    const subAccount = this.lto.account(ofKey(args.key));
    const relationships = this.getRelationships(args.options ?? {});

    const builder = this.builder(account, args.options);
    builder.addVerificationMethod(subAccount, relationships, args.options?.expires);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.lto.broadcast(...builder.transactions);
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const account = this.lto.account(ofIdentifier(args.identifier));

    const builder = this.builder(account, args.options);
    builder.removeVerificationMethod(args.kid);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.lto.broadcast(...builder.transactions);
  }

  async addService(
    args: { identifier: IIdentifier; service: IService; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const account = this.lto.account(ofIdentifier(args.identifier));

    const builder = this.builder(account, args.options);
    builder.addService(args.service);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.lto.broadcast(...builder.transactions);
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: { builder?: IdentityBuilder } },
    context: IAgentContext<IKeyManager>,
  ): Promise<Transaction[]> {
    const account = this.lto.account(ofIdentifier(args.identifier));

    const builder = this.builder(account, args.options);
    builder.removeService(args.id);

    if (args.options?.builder) return []; // Don't broadcast if builder is provided
    return await this.lto.broadcast(...builder.transactions);
  }
}
