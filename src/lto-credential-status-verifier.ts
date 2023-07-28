import {
  IAgentPlugin,
  IAgentContext,
  ICredentialStatusVerifier,
  IResolver,
  CredentialStatus,
  ICheckCredentialStatusArgs,
} from '@veramo/core';
import fetch from 'cross-fetch';

export class LtoCredentialStatusVerifier implements IAgentPlugin {
  readonly methods: ICredentialStatusVerifier;
  readonly schema = {
    components: {
      schemas: undefined,
      methods: undefined,
    },
  };

  readonly url: string;

  constructor(options: { url: string }) {
    this.url = options.url;
    this.methods = { checkCredentialStatus: this.checkCredentialStatus.bind(this) };
  }

  async checkCredentialStatus(
    args: ICheckCredentialStatusArgs,
    context: IAgentContext<IResolver>,
  ): Promise<CredentialStatus> {
    const credential = args.credential;
    const credentialStatus = credential.credentialStatus;
    const issuer = (typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id).replace(
      /\?.+$/,
      '',
    );

    if (credentialStatus?.type !== 'LtoStatusRegistry2023') throw new Error('Unsupported credential status type');

    const response = await fetch(`${this.url}/${credentialStatus.id}?issuer=${issuer}`);
    const status: Record<string, any> = await response.json();

    return {
      id: status.id,
      issuer: status.issuer,
      revoked: !!status.revoked || !!status.suspended,
      issuedAt: status.issued,
      suspendedAt: status.suspended,
      revokedAt: status.revoked,
      statements: status.statements,
    };
  }
}
