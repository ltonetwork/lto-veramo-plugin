import {
  IAgentPlugin,
  IAgentPluginSchema,
  ICreateVerifiableCredentialArgs,
  ICredentialPlugin,
  IssuerAgentContext,
  VerifiableCredential,
  IVerifyCredentialArgs,
  IVerifyResult,
  VerifierAgentContext,
  ICredentialStatusManager,
  CredentialStatusGenerateArgs,
  CredentialStatusUpdateArgs,
  CredentialStatusReference,
  CredentialPayload,
  IAgentContext,
  IDIDManager,
  IKey,
  IIdentifier,
  IssuerType,
} from '@veramo/core';
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import { LtoConnection, LtoOptions } from './lto-connection';
import { Statement } from '@ltonetwork/lto';
import { ofKey } from './convert';
import { TAgent } from '@veramo/core/src/types/IAgent';

interface LtoCredentialStatusGenerateArgs extends CredentialStatusGenerateArgs {
  type: 'LtoStatusRegistry2023';
  credential?: CredentialPayload | VerifiableCredential;
  keyRef?: string;
}

interface LtoCredentialStatusUpdateArgs extends CredentialStatusUpdateArgs {
  vc: VerifiableCredential;
  options?: {
    status: 'issue' | 'revoke' | 'suspend' | 'reinstate' | 'dispute' | 'acknowledge';
    keyRef?: string;
  };
}

export type ManagerAgentContext = IAgentContext<Pick<IDIDManager, 'didManagerGet'>>;

enum StatusStatementType {
  issue = 0x10,
  revoke = 0x11,
  suspend = 0x12,
  reinstate = 0x13,
  dispute = 0x14,
  acknowledge = 0x15,
}

export class LtoCredentialPlugin implements IAgentPlugin {
  readonly _createVerifiableCredential: ICredentialPlugin['createVerifiableCredential'];
  readonly _verifyCredential: ICredentialPlugin['verifyCredential'];
  readonly methods: ICredentialPlugin & ICredentialStatusManager;
  readonly schema?: IAgentPluginSchema;

  readonly lto: LtoConnection;
  readonly addCredentialStatus: boolean;
  readonly issueStatement: boolean;

  constructor(
    plugin: { methods: ICredentialPlugin; schema?: IAgentPluginSchema },
    options: LtoOptions & { addCredentialStatus?: boolean; issueStatement?: boolean },
  ) {
    const { methods, schema } = plugin;

    this.methods = {
      ...methods,
      createVerifiableCredential: this.createVerifiableCredential.bind(this),
      verifyCredential: this.verifyCredential.bind(this),
      credentialStatusGenerate: this.credentialStatusGenerate.bind(this),
      credentialStatusUpdate: this.credentialStatusUpdate.bind(this),
      credentialStatusTypes: this.credentialStatusTypes.bind(this),
    };
    this._createVerifiableCredential = methods.createVerifiableCredential;
    this._verifyCredential = methods.verifyCredential;

    this.schema = schema;

    this.lto = new LtoConnection(options);
    this.addCredentialStatus = options.addCredentialStatus ?? false;
    this.issueStatement = options.issueStatement ?? true;
  }

  private async getIdentifier(
    issuer: IssuerType,
    agent: TAgent<Pick<IDIDManager, 'didManagerGet'>>,
  ): Promise<IIdentifier> {
    if (!agent || !agent.didManagerGet) {
      throw new Error('invalid_setup: your agent does not seem to have IDIDManager plugin installed');
    }

    try {
      return await agent.didManagerGet({ did: typeof issuer === 'string' ? issuer : issuer.id });
    } catch (e) {
      throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`);
    }
  }

  private pickSigningKey(identifier: IIdentifier, keyRef?: string): IKey {
    let key: IKey | undefined;

    if (!keyRef) {
      key = identifier.keys.find((k) => k.type === 'Secp256k1' || k.type === 'Ed25519' || k.type === 'Secp256r1');
      if (!key) throw Error('key_not_found: No signing key for ' + identifier.did);
    } else {
      key = identifier.keys.find((k) => k.kid === keyRef);
      if (!key) throw Error('key_not_found: No signing key for ' + identifier.did + ' with kid ' + keyRef);
    }

    return key as IKey;
  }

  private credentialStatusId(credential: CredentialPayload | VerifiableCredential): Uint8Array {
    const { credentialStatus, proof, ...rest } = credential;
    return sha256(canonicalize(rest) as string);
  }

  async createVerifiableCredential(
    args: ICreateVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential> {
    if (this.addCredentialStatus) {
      args.credential.credentialStatus = await this.credentialStatusGenerate(
        { type: 'LtoStatusRegistry2023', ...args },
        context,
      );
    }

    return this._createVerifiableCredential(args, context);
  }

  async verifyCredential(args: IVerifyCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
    const result = await this._verifyCredential(args, context);

    const { credential } = args;

    if (
      result.verified &&
      typeof credential !== 'string' &&
      credential.credentialStatus?.type === 'LtoStatusRegistry2023'
    ) {
      const id = this.credentialStatusId(credential);

      if (credential.credentialStatus.id !== base58.encode(id)) {
        result.verified = false;
        result.error = {
          errorCode: 'invalid_credential_status_id',
          message:
            'invalid_credential_status_id: ' +
            'Credential status id is not a base58 encoded sha256 hash of the credential',
        };
      }
    }

    return result;
  }

  async credentialStatusGenerate(
    args: LtoCredentialStatusGenerateArgs,
    context?: ManagerAgentContext,
  ): Promise<CredentialStatusReference> {
    const { type, credential } = args;
    if (type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');

    const id = this.credentialStatusId(credential);

    if (this.issueStatement) {
      const identifier = await this.getIdentifier(credential.issuer, context.agent);
      const key = this.pickSigningKey(identifier, args.keyRef);
      await this.submitStatus(id, StatusStatementType.issue, key);
    }

    return { id: base58.encode(id), type: 'LtoStatusRegistry2023' };
  }

  private async submitStatus(id: Uint8Array, status: StatusStatementType, key: IKey): Promise<void> {
    const sender = this.lto.account(ofKey(key));

    const tx = new Statement(status, undefined, id).signWith(sender);
    await this.lto.broadcast(tx);
  }

  async credentialStatusUpdate(args: LtoCredentialStatusUpdateArgs, context?: ManagerAgentContext): Promise<void> {
    const { vc, options } = args;
    const { status } = options ?? {};

    if (!status) throw new Error('Missing status option');
    if (vc.credentialStatus?.type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');

    const id = base58.decode(vc.credentialStatus.id);
    const statementType = StatusStatementType[status];

    const identifier = await this.getIdentifier(vc.issuer, context?.agent);
    const key = this.pickSigningKey(identifier, args.options.keyRef);

    await this.submitStatus(id, StatusStatementType.issue, key);
  }

  async credentialStatusTypes() {
    return ['LtoStatusRegistry2023'];
  }
}
