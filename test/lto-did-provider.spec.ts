import { expect } from 'chai';
import * as sinon from 'sinon';
import { LtoDIDProvider } from '../src';
import { IAgentContext, IIdentifier, IKeyManager, TKeyType } from '@veramo/core';
import LTO, { Account, Anchor, Association, PublicNode, Register, Statement } from '@ltonetwork/lto';

describe('LtoDIDProvider', () => {
  let ltoDIDProvider: LtoDIDProvider;

  let lto: LTO;
  let node: sinon.SinonStubbedInstance<PublicNode>;

  let context: IAgentContext<IKeyManager>;
  let agent: sinon.SinonStubbedInstance<IKeyManager>;
  let account: Account;
  let identifier: IIdentifier;

  beforeEach(() => {
    lto = new LTO('T');

    node = sinon.createStubInstance(PublicNode);
    (node as any).url = 'https://example.com';
    node.broadcast.returnsArg(0);

    lto.node = node;

    account = lto.account({ seed: 'test' });
    sinon.stub(lto.accountFactories.ed25519, 'create').returns(account);
  });

  beforeEach(() => {
    agent = { keyManagerImport: sinon.stub().resolves(), keyManagerRemove: sinon.stub() } as any;
    context = { agent } as any;

    ltoDIDProvider = new LtoDIDProvider({
      defaultKms: 'kms',
      lto: lto,
    });

    identifier = {
      did: `did:lto:${account.address}`,
      controllerKeyId: `did:lto:${account.address}#sign`,
      keys: [
        {
          kid: `did:lto:${account.address}#sign`,
          kms: 'kms',
          type: 'Ed25519' as TKeyType,
          publicKeyHex: account.signKey.publicKey.hex,
          privateKeyHex: account.signKey.privateKey.hex,
        },
      ],
      services: [],
      provider: 'did:lto',
    };
  });

  describe('createIdentifier', () => {
    it('should create an identifier with minimal options', async () => {
      const createIdentifierOptions = { kms: 'kms' };

      await ltoDIDProvider.createIdentifier(createIdentifierOptions, context);

      expect(agent.keyManagerImport.called).to.be.true;
      expect(agent.keyManagerImport.args[0][0]).to.deep.eq({
        kid: `${account.did}#sign`,
        kms: 'kms',
        privateKeyHex: account?.signKey.privateKey!.hex,
        publicKeyHex: account?.signKey.publicKey.hex,
        type: 'Ed25519',
        meta: {
          address: account.address,
          seed: account.seed,
          nonce: 0,
        },
      });

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Anchor);

      const tx = node.broadcast.args[0][0] as Anchor;
      expect(tx.sender).to.eq(account.address);
    });

    it('should create an identifier with relationships', async () => {
      const identifierOptions = { authentication: true };
      const createIdentifierOptions = { kms: 'kms', options: identifierOptions };

      await ltoDIDProvider.createIdentifier(createIdentifierOptions, context);

      expect(agent.keyManagerImport.called).to.be.true; // Test transaction here
    });

    it('should create an identifier with verification methods', async () => {
      const verificationMethod = { seed: 'test', nonce: 1 };
      const identifierOptions = { verificationMethods: [verificationMethod] };
      const createIdentifierOptions = { kms: 'kms', options: identifierOptions };

      await ltoDIDProvider.createIdentifier(createIdentifierOptions, context);

      expect(agent.keyManagerImport.called).to.be.true; // Test transaction here
    });
  });

  describe('deleteIdentifier', () => {
    it('should delete an identifier', async () => {
      const result = await ltoDIDProvider.deleteIdentifier(identifier, context);

      expect(result).to.be.true;

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Statement);

      const tx = node.broadcast.args[0][0] as Statement;
      expect(tx.sender).to.eq(account.address);
      expect(tx.statementType).to.equal(0x120);
    });
  });

  describe('addKey', () => {
    it('should add a key', async () => {
      const subAccount = lto.account({ seed: 'test', nonce: 1 });

      const key = {
        kid: `${subAccount.did}#sign`,
        kms: 'kms',
        type: 'Ed25519' as TKeyType,
        publicKeyHex: subAccount.signKey.publicKey.hex,
        privateKeyHex: subAccount.signKey.privateKey.hex,
      };

      const txs = await ltoDIDProvider.addKey({ identifier, key }, context);

      expect(txs).to.have.length(2);
      expect(txs[0]).to.be.instanceOf(Register);
      expect(txs[1]).to.be.instanceOf(Association);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Register);
      expect(node.broadcast.args[1][0]).to.be.instanceOf(Association);

      const registerTx = node.broadcast.args[0][0] as Register;
      expect(registerTx.sender).to.eq(account.address);
      expect(registerTx.accounts).to.have.length(1);
      expect(registerTx.accounts[0]).to.deep.equal({ keyType: 'ed25519', publicKey: subAccount.publicKey });

      const associationTx = node.broadcast.args[1][0] as Association;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.recipient).to.eq(subAccount.address);
      expect(associationTx.associationType).to.eq(0x100);
      expect(associationTx.data).to.have.length(0);
    });
  });
});
