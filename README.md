![lto-veramo](https://github.com/ltonetwork/lto-veramo/assets/100821/ef26b8c6-82d4-4911-afe7-85dedd621a3a)

This library provides [Veramo](https://veramo.io/) plugins to manage DIDs and verifiable credentials on LTO Network.

## Installation

To install the library, you can use npm or yarn:

```shell
npm install @ltonetwork/veramo-plugin
```

or

```shell
yarn add @ltonetwork/veramo-plugin
```

## LTO DID provider

The LTO DID provider allows you to manage DIDs on the LTO Network blockchain.

### Usage

```typescript
import { createAgent } from '@veramo/core'
import { DIDManager } from '@veramo/did-manager'
import { LtoDidProvider } from '@lto-network/veramo-plugin'

const agent = createAgent<DIDManager>({
  plugins: [
    new DIDManager({
      defaultProvider: 'did:lto',
      providers: {
        'did:lto': new LtoDidProvider({
          nodeAddress: 'https://testnet.lto.network',
          networkId: 'T',
        }),
      },
    }),
  ],
})
```

#### Options

The LTO DID provider accepts the following options:

| Name          | Type       | Description                                         |
|---------------|------------|-----------------------------------------------------|
| defaultKms    | string     | The default key management system (KMS).            |
| lto           | LTO        | Optional. The `LTO` instance.                       |
| networkId     | string     | `T` for testnet or `L` for mainnet. Defaults to `L` |
| nodeAddress   | string     | Optional. URL of your LTO public node.              |
| nodeApiKey    | string     | Optional. The node API key.                         |
| sponsor       | Account    | Optional. The sponsor account or information.       |

In case an `LTO` instance is not provided, the provider will create one using the `networkId`, `nodeAddress` and
`nodeApiKey` options.

#### Sponsor

The `sponsor` option can be used to automatically sponsor the transaction fees for new DIDs. It can be either an
`Account` object or account settings.

```typescript
new LtoDidProvider({
  nodeAddress: 'https://testnet.lto.network',
  networkId: 'T',
  sponsor: {
    seed: 'my seed',
    keyType: 'ed25519',
    address: '3JfLsayRvWbJh2JjEhCnfr6hKv8L1xUkH9p',
  },
});
```

Only `seed` or `privateKey` is required.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please create an issue or
submit a pull request on the [GitHub repository](https://github.com/ltonetwork/lto-veramo-plugin).

## License

This library is licensed under the [MIT License](LICENSE).
