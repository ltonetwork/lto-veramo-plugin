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
  IKeyManager,
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

export type ManagerAgentContext = IAgentContext<
  Pick<IDIDManager, 'didManagerGet'> & Pick<IKeyManager, 'keyManagerGet'>
>;

enum StatusStatementType {
  issue = 0x10,
  revoke = 0x11,
  suspend = 0x12,
  reinstate = 0x13,
  dispute = 0x14,
  acknowledge = 0x15,
}

interface IssueOpts {
  addCredentialStatus?: boolean;
  issueStatement?: boolean;
}
interface VerifyOpts {
  acceptUnknownStatus?: boolean;
}

export class LtoCredentialPlugin implements IAgentPlugin {
  readonly _createVerifiableCredential: ICredentialPlugin['createVerifiableCredential'];
  readonly _verifyCredential: ICredentialPlugin['verifyCredential'];
  readonly methods: ICredentialPlugin & ICredentialStatusManager;
  readonly schema?: IAgentPluginSchema;

  readonly lto: LtoConnection;
  readonly addCredentialStatus: boolean;
  readonly issueStatement: boolean;
  readonly acceptUnknownStatus: boolean;

  constructor(
    plugin: { methods: ICredentialPlugin; schema?: IAgentPluginSchema },
    options: LtoOptions & IssueOpts & VerifyOpts = {},
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
    this.acceptUnknownStatus = options.acceptUnknownStatus ?? !this.issueStatement;
  }

  private async getIdentifier(
    issuer: IssuerType,
    agent: TAgent<Pick<IDIDManager, 'didManagerGet'>>,
  ): Promise<IIdentifier> {
    if (!agent?.didManagerGet) {
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
      const credential = await this._createVerifiableCredential({ ...args, save: false }, context);

      delete credential.proof;
      args.credential = credential as CredentialPayload;

      args.credential.credentialStatus = await this.credentialStatusGenerate(
        { type: 'LtoStatusRegistry2023', ...args },
        context,
      );
    }

    return this._createVerifiableCredential(args, context);
  }

  async verifyCredential(args: IVerifyCredentialArgs, context: VerifierAgentContext): Promise<IVerifyResult> {
    const { credential } = args;

    if (typeof credential === 'string' || credential.credentialStatus?.type !== 'LtoStatusRegistry2023') {
      return this._verifyCredential(args, context);
    }

    const result = await this._verifyCredential(
      { ...args, policies: { ...args.policies, credentialStatus: false } },
      context,
    );

    if (result.verified && credential.credentialStatus.id !== base58.encode(this.credentialStatusId(credential))) {
      result.verified = false;
      result.error = {
        errorCode: 'invalid_credential_status_id',
        message:
          'invalid_credential_status_id: Credential status id is not a base58 encoded sha256 hash of the credential',
      };
    }

    if (!result.verified || args.policies?.credentialStatus === false) return result;

    if (typeof context.agent.checkCredentialStatus !== 'function') {
      throw new Error(
        `invalid_setup: The credential status can't be verified because there is no ICredentialStatusVerifier plugin installed.`,
      );
    }

    const status = await context.agent.checkCredentialStatus({ credential });

    if (
      !status.issuedAt &&
      !this.acceptUnknownStatus &&
      Math.abs(new Date(credential.issuanceDate).getTime() - Date.now()) > 300_000
    ) {
      return {
        verified: false,
        error: {
          message: 'unknown_status: There is no on-chain record of the credential being issued',
          errorCode: 'unknown_status',
        },
      };
    }

    if (
      status.issuedAt &&
      Math.abs(new Date(credential.issuanceDate).getTime() - new Date(status.issuedAt).getTime()) > 300_000
    ) {
      return {
        verified: false,
        credentialStatus: status,
        error: {
          message:
            'issue_statement_elapsed: The on-chain statement has been published more than 5 minutes after the credential was issued',
          errorCode: 'issue_statement_elapsed',
        },
      };
    }

    if (status.suspendedAt) {
      return {
        verified: false,
        credentialStatus: status,
        error: {
          message: 'suspended: The credential was suspended by the issuer',
          errorCode: 'suspended',
        },
      };
    }

    if (status.revokedAt) {
      return {
        verified: false,
        credentialStatus: status,
        error: {
          message: 'revoked: The credential was revoked by the issuer',
          errorCode: 'revoked',
        },
      };
    }

    result.credentialStatus = status;
    return result;
  }

  async credentialStatusGenerate(
    args: LtoCredentialStatusGenerateArgs,
    context?: ManagerAgentContext,
  ): Promise<CredentialStatusReference> {
    const { type, credential } = args;
    if (type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');
    if (!credential) throw new Error('No credential argument provided');

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

    let key: IKey;

    if (statementType === StatusStatementType.dispute || statementType === StatusStatementType.acknowledge) {
      if (!context?.agent.keyManagerGet) {
        throw new Error('invalid_setup: your agent does not seem to have IKeyManager plugin installed');
      }
      if (!options?.keyRef) throw new Error('The keyRef option is required for dispute and acknowledge statements');

      key = await context.agent.keyManagerGet({ kid: options.keyRef });
      if (!key) throw Error(`key_not_found: No key with kid ${options.keyRef}`);
    } else {
      const identifier = await this.getIdentifier(vc.issuer, context?.agent);
      key = this.pickSigningKey(identifier, options?.keyRef);
    }

    await this.submitStatus(id, statementType, key);
  }

  async credentialStatusTypes() {
    return ['LtoStatusRegistry2023'];
  }
}
