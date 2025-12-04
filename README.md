<!--
SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.

SPDX-License-Identifier: MIT
-->

# @semiotic-labs/agentium-sdk

A TypeScript SDK to simplify interaction with the `/v1/identity/connect` API endpoint.

## Installation

Install the package using npm:

```bash
npm install @semiotic-labs/agentium-sdk
```

## Usage

### Basic Usage

To connect to the default production API:

```typescript
import { AgentiumClient } from '@semiotic-labs/agentium-sdk';

const client = new AgentiumClient();

async function connectIdentity() {
  try {
    const googleToken = 'YOUR_GOOGLE_JWT'; // Replace with your actual Google JWT
    const response = await client.connectGoogleIdentity(googleToken);
    console.log('Connected Identity:', response);
  } catch (error) {
    console.error('Failed to connect identity:', error);
  }
}

connectIdentity();
```

### Advanced Usage: Custom Endpoint

You can specify a custom `baseURL` in the constructor, which is useful for testing against local or staging environments.

```typescript
import { AgentiumClient } from '@semiotic-labs/agentium-sdk';

// Example for a local development server
const localClient = new AgentiumClient({
  baseURL: 'http://localhost:8080',
});

async function connectIdentityLocal() {
  try {
    const googleToken = 'YOUR_GOOGLE_JWT';
    const response = await localClient.connectGoogleIdentity(googleToken);
    console.log('Connected Identity (Local):', response);
  } catch (error) {
    console.error('Failed to connect identity (Local):', error);
  }
}

connectIdentityLocal();
```

## For Developers

### Project Setup

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```

### REUSE Compliance

This project follows the [REUSE Specification](https://reuse.software/spec/). To ensure compliance:

1.  **Install REUSE Tool:** You'll need to install the `reuse` command-line tool globally via `pip`:
    ```bash
    pip install reuse
    ```
### Applying SPDX Headers

To add or update SPDX license and copyright headers to all relevant files:

```bash
npm run reuse:write
```

### Verify Compliance

To check if the project is fully REUSE compliant:

```bash
npm run reuse:check
```

### Running Tests

To run the test suite:

```bash
npm test
```

### Building the Project

To compile the TypeScript code into JavaScript in the `dist` folder:

```bash
npm run build
```
