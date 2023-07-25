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
} from '@veramo/core';
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import { LtoConnection, LtoOptions } from './lto-connection';
import { Statement } from '@ltonetwork/lto';

interface LtoCredentialStatusGenerateArgs extends CredentialStatusGenerateArgs {
  type: 'LtoStatusRegistry2023';
  credential: CredentialPayload | VerifiableCredential;
}

interface LtoCredentialStatusUpdateArgs extends CredentialStatusUpdateArgs {
  vc: VerifiableCredential;
  options?: {
    status: 'issue' | 'revoke' | 'suspend' | 'reinstate' | 'dispute' | 'acknowledge';
  };
}

enum LtoCredentialStatusStatementType {
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

  private credentialStatusId(credential: CredentialPayload | VerifiableCredential): Uint8Array {
    const { credentialStatus, proof, ...rest } = credential;
    return sha256(canonicalize(rest) as string);
  }

  async createVerifiableCredential(
    args: ICreateVerifiableCredentialArgs,
    context: IssuerAgentContext,
  ): Promise<VerifiableCredential> {
    const { credential } = args;
    if (this.addCredentialStatus) {
      credential.credentialStatus = await this.credentialStatusGenerate({ type: 'LtoStatusRegistry2023', ...args });
    }

    return this._createVerifiableCredential({ ...args, credential }, context);
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

  async credentialStatusGenerate(args: LtoCredentialStatusGenerateArgs): Promise<CredentialStatusReference> {
    const { type, credential } = args;
    if (type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');

    const id = this.credentialStatusId(credential);

    if (this.issueStatement) {
      await this.lto.broadcast(new Statement(LtoCredentialStatusStatementType.issue, undefined, id));
    }

    return { id: base58.encode(id), type: 'LtoStatusRegistry2023' };
  }

  async credentialStatusUpdate(args: LtoCredentialStatusUpdateArgs): Promise<void> {
    const { vc, options } = args;
    const { status } = options ?? {};

    if (!status) throw new Error('Missing status option');
    if (vc.credentialStatus?.type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');

    const id = base58.decode(vc.credentialStatus.id);
    const statementType = LtoCredentialStatusStatementType[status];

    await this.lto.broadcast(new Statement(statementType, undefined, id));
  }

  async credentialStatusTypes() {
    return ['LtoStatusRegistry2023'];
  }
}
