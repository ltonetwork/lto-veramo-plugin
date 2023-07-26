import { IAccountIn, ISigner } from '@ltonetwork/lto/interfaces';
import LTO, { Account, Binary, PublicNode, Transaction } from '@ltonetwork/lto';

interface LtoOptionsWithLTO {
  lto: LTO;
  networkId?: never;
  nodeAddress?: never;
  nodeApiKey?: never;
  sponsor?: ISigner | IAccountIn;
}
interface LtoOptionsWithSettings {
  lto?: never;
  networkId?: string;
  nodeAddress?: string;
  nodeApiKey?: string;
  sponsor?: ISigner | IAccountIn;
}
export type LtoOptions = LtoOptionsWithLTO | LtoOptionsWithSettings;

export interface AccountOptions extends IAccountIn {
  publicKeyHex?: string;
  privateKeyHex?: string;
}

export class LtoConnection {
  readonly lto: LTO;
  readonly sponsor?: Account;

  constructor(options: LtoOptions) {
    if ('lto' in options) {
      this.lto = options.lto;
    } else {
      this.lto = new LTO(options.networkId);

      if (options.nodeAddress || options.nodeApiKey) {
        this.lto.node = new PublicNode(options.nodeAddress, options.nodeApiKey);
      }
    }

    if (options.sponsor) {
      this.sponsor = options.sponsor instanceof Account ? options.sponsor : this.lto.account(options.sponsor);
    }
  }

  async broadcast(...tsx: Transaction[]): Promise<Transaction[]> {
    if (this.sponsor) {
      tsx.forEach((tx) => tx.sender !== this.sponsor.address && tx.sponsorWith(this.sponsor));
    }

    return Promise.all(tsx.map((tx) => this.lto.node.broadcast(tx)));
  }

  account(options: AccountOptions): Account {
    const { publicKeyHex, privateKeyHex, ...accountOptions } = options;
    if (publicKeyHex) accountOptions.publicKey = Binary.fromHex(publicKeyHex);
    if (privateKeyHex) accountOptions.privateKey = Binary.fromHex(privateKeyHex);

    return this.lto.account(options);
  }
}
