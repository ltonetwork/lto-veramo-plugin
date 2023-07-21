import { expect } from 'chai';
import * as sinon from 'sinon';
import { LtoDIDProvider } from '../src';
import { IAgentContext, IIdentifier, IKey, IKeyManager, TKeyType } from '@veramo/core';
import LTO, {
  Account,
  Anchor,
  Association,
  Binary,
  Data,
  IdentityBuilder,
  PublicNode,
  Register,
  RevokeAssociation,
  Statement,
} from '@ltonetwork/lto';

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
      await ltoDIDProvider.createIdentifier({}, context);

      expect(agent.keyManagerImport.called).to.be.true;
      expect(agent.keyManagerImport.args[0][0]).to.deep.eq({
        kid: `${account.did}#sign`,
        kms: 'kms',
        privateKeyHex: account.signKey.privateKey!.hex,
        publicKeyHex: account.signKey.publicKey.hex,
        type: 'Ed25519',
        meta: {
          address: account.address,
          seed: account.seed,
          nonce: 0,
        },
      });
      expect(agent.keyManagerImport.args[1][0]).to.deep.eq({
        kid: `${account.did}#encrypt`,
        kms: 'kms',
        privateKeyHex: account.encryptKey.privateKey!.hex,
        publicKeyHex: account.encryptKey.publicKey.hex,
        type: 'X25519',
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

    it('should create an identifier from seed', async () => {
      const accountOptions = { seed: 'my seed', nonce: new Binary('nonce') };
      const account = lto.account(accountOptions);

      await ltoDIDProvider.createIdentifier({ options: accountOptions }, context);

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
          nonce: 'base64:bm9uY2U=',
        },
      });

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Anchor);

      const tx = node.broadcast.args[0][0] as Anchor;
      expect(tx.sender).to.eq(account.address);
    });

    it('should create an identifier with relationships', async () => {
      const options = { capabilityInvocation: true, capabilityDelegation: true };

      await ltoDIDProvider.createIdentifier({ options }, context);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Association);

      const tx = node.broadcast.args[0][0] as Association;
      expect(tx.sender).to.eq(account.address);
      expect(tx.recipient).to.eq(account.address);
      expect(tx.associationType).to.eq(0x100);
      expect(tx.data).to.have.length(2);
      expect(tx.data).to.deep.includes({ key: 'capabilityInvocation', type: 'boolean', value: true });
      expect(tx.data).to.deep.includes({ key: 'capabilityDelegation', type: 'boolean', value: true });
    });

    it('should create an identifier with verification methods', async () => {
      const verificationMethods = [
        { seed: 'test', nonce: 1 },
        { seed: 'test', nonce: 2, authentication: true, assertionMethod: true },
      ];

      const subAccount1 = lto.account(verificationMethods[0]);
      const subAccount2 = lto.account(verificationMethods[1]);

      await ltoDIDProvider.createIdentifier({ kms: 'kms', options: { verificationMethods } }, context);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Register);
      expect(node.broadcast.args[1][0]).to.be.instanceOf(Association);
      expect(node.broadcast.args[1][0]).to.be.instanceOf(Association);

      const registerTx = node.broadcast.args[0][0] as Register;
      expect(registerTx.sender).to.eq(account.address);
      expect(registerTx.accounts).to.have.length(2);
      expect(registerTx.accounts).to.deep.includes({ keyType: 'ed25519', publicKey: subAccount1.publicKey });
      expect(registerTx.accounts).to.deep.includes({ keyType: 'ed25519', publicKey: subAccount2.publicKey });

      const assocTx1 = node.broadcast.args[1][0] as Association;
      expect(assocTx1.sender).to.eq(account.address);
      expect(assocTx1.recipient).to.eq(lto.account(verificationMethods[0]).address);
      expect(assocTx1.associationType).to.eq(0x100);
      expect(assocTx1.data).to.have.length(0);

      const assocTx2 = node.broadcast.args[2][0] as Association;
      expect(assocTx2.sender).to.eq(account.address);
      expect(assocTx2.recipient).to.eq(lto.account(verificationMethods[1]).address);
      expect(assocTx2.associationType).to.eq(0x100);
      expect(assocTx2.data).to.have.length(2);
      expect(assocTx2.data).to.deep.includes({ key: 'authentication', type: 'boolean', value: true });
      expect(assocTx2.data).to.deep.includes({ key: 'assertionMethod', type: 'boolean', value: true });
    });

    it('should create an identifier with services', async () => {
      const services = [
        { id: '#foo', type: 'test', serviceEndpoint: 'https://foo.example.com' },
        { id: '#bar', type: 'test', serviceEndpoint: 'https://bar.example.com' },
      ];

      await ltoDIDProvider.createIdentifier({ kms: 'kms', options: { services } }, context);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.be.instanceOf(Data);

      const dataTx = node.broadcast.args[0][0] as Data;
      expect(dataTx.sender).to.eq(account.address);
      expect(dataTx.data).to.have.length(2);
      expect(dataTx.data).to.deep.includes({
        key: 'did:service:foo',
        type: 'string',
        value: '{"id":"#foo","type":"test","serviceEndpoint":"https://foo.example.com"}',
      });
      expect(dataTx.data).to.deep.includes({
        key: 'did:service:bar',
        type: 'string',
        value: '{"id":"#bar","type":"test","serviceEndpoint":"https://bar.example.com"}',
      });
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
    let subAccount: Account;
    let key: IKey;

    beforeEach(() => {
      subAccount = lto.account({ seed: 'test', nonce: 1 });

      key = {
        kid: `${subAccount.did}#sign`,
        kms: 'kms',
        type: 'Ed25519' as TKeyType,
        publicKeyHex: subAccount.signKey.publicKey.hex,
        privateKeyHex: subAccount.signKey.privateKey.hex,
      };
    });

    it('should add a key', async () => {
      const txs = await ltoDIDProvider.addKey({ identifier, key }, context);

      expect(txs).to.have.length(2);
      expect(txs[0]).to.be.instanceOf(Register);
      expect(txs[1]).to.be.instanceOf(Association);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.equal(txs[0]);
      expect(node.broadcast.args[1][0]).to.equal(txs[1]);

      const registerTx = txs[0] as Register;
      expect(registerTx.sender).to.eq(account.address);
      expect(registerTx.accounts).to.have.length(1);
      expect(registerTx.accounts[0]).to.deep.equal({ keyType: 'ed25519', publicKey: subAccount.publicKey });

      const associationTx = txs[1] as Association;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.recipient).to.eq(subAccount.address);
      expect(associationTx.associationType).to.eq(0x100);
      expect(associationTx.data).to.have.length(0);
    });

    it('should add a key with verification relationships and expiry', async () => {
      const options = {
        authentication: true,
        assertionMethod: true,
        expires: new Date('2030-01-01T00:00:00.000Z'),
      };

      const txs = await ltoDIDProvider.addKey({ identifier, key, options }, context);

      expect(txs).to.have.length(2);
      expect(txs[0]).to.be.instanceOf(Register);
      expect(txs[1]).to.be.instanceOf(Association);

      const registerTx = txs[0] as Register;
      expect(registerTx.sender).to.eq(account.address);
      expect(registerTx.accounts).to.have.length(1);
      expect(registerTx.accounts[0]).to.deep.equal({ keyType: 'ed25519', publicKey: subAccount.publicKey });

      const associationTx = txs[1] as Association;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.recipient).to.eq(subAccount.address);
      expect(associationTx.associationType).to.eq(0x100);
      expect(associationTx.expires).to.eq(options.expires.getTime());
      expect(associationTx.data).to.have.length(2);
      expect(associationTx.data).to.deep.includes({ key: 'authentication', type: 'boolean', value: true });
      expect(associationTx.data).to.deep.includes({ key: 'assertionMethod', type: 'boolean', value: true });
    });
  });

  describe('removeKey', () => {
    let subAccount: Account;

    beforeEach(() => {
      subAccount = lto.account({ seed: 'test', nonce: 1 });
    });

    it('should remove a key', async () => {
      const kid = `${subAccount.did}#sign`;
      const txs = await ltoDIDProvider.removeKey({ identifier, kid }, context);

      expect(txs).to.have.length(1);
      expect(txs[0]).to.be.instanceOf(RevokeAssociation);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.equal(txs[0]);

      const associationTx = txs[0] as RevokeAssociation;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.recipient).to.eq(subAccount.address);
      expect(associationTx.associationType).to.eq(0x100);
    });
  });

  describe('addService', () => {
    it('should broadcast a Data tx to add a service', async () => {
      const service = { id: '#test', type: 'test', serviceEndpoint: 'https://example.com' };

      const txs = await ltoDIDProvider.addService({ identifier, service }, context);

      expect(txs).to.have.length(1);
      expect(txs[0]).to.be.instanceOf(Data);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.equal(txs[0]);

      const associationTx = txs[0] as Data;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.data).to.have.length(1);
      expect(associationTx.data).to.deep.includes({
        key: 'did:service:test',
        type: 'string',
        value: '{"id":"#test","type":"test","serviceEndpoint":"https://example.com"}',
      });
    });
  });

  describe('removeService', () => {
    it('should broadcast a Data tx to remove a service', async () => {
      const txs = await ltoDIDProvider.removeService({ identifier, id: '#test' }, context);

      expect(txs).to.have.length(1);
      expect(txs[0]).to.be.instanceOf(Data);

      expect(node.broadcast.called).to.be.true;
      expect(node.broadcast.args[0][0]).to.equal(txs[0]);

      const associationTx = txs[0] as Data;
      expect(associationTx.sender).to.eq(account.address);
      expect(associationTx.data).to.have.length(1);
      expect(associationTx.data).to.deep.includes({ key: 'did:service:test', type: 'boolean', value: false });
    });
  });

  describe('sponsor transactions', () => {
    let sponsor: Account;

    beforeEach(() => {
      ltoDIDProvider = new LtoDIDProvider({
        defaultKms: 'kms',
        lto: lto,
        sponsor: { seed: 'sponsor' },
      });

      sponsor = lto.account({ seed: 'sponsor' });
    });

    it('should have a sponsor', () => {
      expect(ltoDIDProvider.sponsor?.address).to.eq(sponsor.address);
    });

    it('should sponsor tx for identifier creation', async () => {
      await ltoDIDProvider.createIdentifier({}, context);

      const txs = node.broadcast.args.map((args) => args[0]);
      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx for identifier creation with verification methods and services', async () => {
      const verificationMethods = [{ seed: 'test', nonce: 1 }];
      const services = [{ id: '#test', type: 'test', serviceEndpoint: 'https://example.com' }];

      await ltoDIDProvider.createIdentifier({ options: { verificationMethods, services } }, context);

      const txs = node.broadcast.args.map((args) => args[0]);
      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx for identifier deletion', async () => {
      await ltoDIDProvider.deleteIdentifier(identifier, context);

      const txs = node.broadcast.args.map((args) => args[0]);
      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx when adding a key', async () => {
      const subAccount = lto.account({ seed: 'test', nonce: 1 });
      const key = {
        kid: `${subAccount.did}#sign`,
        kms: 'kms',
        type: 'Ed25519' as TKeyType,
        publicKeyHex: subAccount.signKey.publicKey.hex,
        privateKeyHex: subAccount.signKey.privateKey.hex,
      };

      const txs = await ltoDIDProvider.addKey({ identifier, key }, context);

      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx when removing a key', async () => {
      const subAccount = lto.account({ seed: 'test', nonce: 1 });

      const txs = await ltoDIDProvider.removeKey({ identifier, kid: `${subAccount.did}#sign` }, context);

      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx when adding a service', async () => {
      const service = { id: '#test', type: 'test', serviceEndpoint: 'https://example.com' };

      const txs = await ltoDIDProvider.addService({ identifier, service }, context);

      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });

    it('should sponsor tx when removing a service', async () => {
      const txs = await ltoDIDProvider.removeService({ identifier, id: '#test' }, context);

      for (const tx of txs) {
        expect(tx.sponsor).to.eq(sponsor.address);
      }
    });
  });

  describe('using builder', () => {
    let builder: IdentityBuilder;

    beforeEach(() => {
      builder = new IdentityBuilder(account);
    });

    it('should not broadcast when adding a key', async () => {
      const subAccount = lto.account({ seed: 'test', nonce: 1 });
      const key = {
        kid: `${subAccount.did}#sign`,
        kms: 'kms',
        type: 'Ed25519' as TKeyType,
        publicKeyHex: subAccount.signKey.publicKey.hex,
        privateKeyHex: subAccount.signKey.privateKey.hex,
      };

      const txs = await ltoDIDProvider.addKey({ identifier, key, options: { builder } }, context);

      expect(txs).to.have.length(0);
      expect(node.broadcast.called).to.be.false;

      expect(builder.newMethods).to.have.length(1);
    });

    it('should not broadcast when removing a key', async () => {
      const subAccount = lto.account({ seed: 'test', nonce: 1 });

      const txs = await ltoDIDProvider.removeKey(
        { identifier, kid: `${subAccount.did}#sign`, options: { builder } },
        context,
      );

      expect(txs).to.have.length(0);
      expect(node.broadcast.called).to.be.false;

      expect(builder.removedMethods).to.have.length(1);
    });

    it('should not broadcast when adding a service', async () => {
      const service = { id: '#test', type: 'test', serviceEndpoint: 'https://example.com' };

      const txs = await ltoDIDProvider.addService({ identifier, service, options: { builder } }, context);

      expect(txs).to.have.length(0);
      expect(node.broadcast.called).to.be.false;

      expect(builder.newServices).to.have.length(1);
    });

    it('should not broadcast when removing a service', async () => {
      const txs = await ltoDIDProvider.removeService({ identifier, id: '#test', options: { builder } }, context);

      expect(txs).to.have.length(0);
      expect(node.broadcast.called).to.be.false;

      expect(builder.removedServices).to.have.length(1);
    });

    it('should throw an error when the builder is not for the same account', async () => {
      const otherAccount = lto.account({ seed: 'other' });
      builder = new IdentityBuilder(otherAccount);

      try {
        await ltoDIDProvider.removeService({ identifier, id: '#test', options: { builder } }, context);
        expect.fail('Should throw an error');
      } catch (e) {
        expect(e).to.be.instanceOf(Error);
        expect(e.message).to.eq('Builder account does not match identifier management key');
      }
    });
  });
});
