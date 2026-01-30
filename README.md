# Auth Module

This module handles authentication and authorization logic for the Omniflow server.

## 🏗️ Structure

This module is a **composite** of standard core logic and application-specific extensions.

*   **`core/`**: (Git Submodule) Contains the standardized `omniflow-auth-core` library.
    *   *Source*: [https://github.com/ArtemisSaber/omniflow-auth-core](https://github.com/ArtemisSaber/omniflow-auth-core)
    *   *Managed via*: NPM Workspace.
*   **`custom/`**: Contains overrides and extensions specific to this server instance.
*   **`auth.test.ts`**: Integration tests verifying the assembled module (Core + Custom).

## 🚀 Usage

The core logic is imported directly:

```typescript
import { AuthRoutes } from './core/auth.routes';
// or via the workspace package name if configured
```

## 🛠️ Development

*   **Update Core**: `git submodule update --remote src/modules/auth/core`
*   **Test**: `npm test src/modules/auth`
