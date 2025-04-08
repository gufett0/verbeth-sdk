# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs.

## Features
- Stateless encrypted messaging
- Ephemeral keys & forward secrecy
- Minimal on-chain interface

## Usage (WIP)
```ts
import { decryptLog } from '@verbeth/sdk'

const msg = decryptLog(eventLog, mySecretKey);
```
