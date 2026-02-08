# mask-token

> Secure token masking with NIST/PCI-DSS/OWASP compliance

[![npm version](https://img.shields.io/npm/v/mask-token.svg)](https://www.npmjs.com/package/mask-token)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/mask-token)](https://bundlephobia.com/package/mask-token)

Token masking library for JavaScript/TypeScript. Masks API keys, secrets, and tokens while preserving context for debugging and compliance.

## ✨ Features

- 🔒 **Security-First**: NIST SP 800-122, PCI-DSS, and OWASP A02 compliant
- 🎯 **Smart Detection**: Auto-detects 43+ token types (NPM, GitHub, Stripe, AWS, etc.)
- 🛡️ **Entropy-Safe**: Fixed-length masking prevents length-based attacks
- ⚠️ **Input Validation**: Detects and warns about placeholder values and mistakes
- 🎨 **Customizable**: 4 built-in presets + full configuration options
- 📦 **Lightweight**: ~5 KB gzipped, zero dependencies
- 🔧 **TypeScript**: Full type safety with comprehensive IntelliSense
- 🌳 **Tree-Shakeable**: ESM exports for optimal bundle size

## 📦 Installation

```bash
npm install @ekaone/mask-token
```

```bash
yarn add @ekaone/mask-token
```

```bash
pnpm add @ekaone/mask-token
```

## 🚀 Quick Start

```typescript
import { maskToken } from '@ekaone/mask-token';

// Basic usage - auto-detects token type
maskToken('npm_a1b2c3d4e5f6g7h8i9j0');
// → 'npm_••••••••i9j0'

// Works with GitHub tokens
maskToken('ghp_abcdefghijklmnopqrstuvwxyz123456');
// → 'ghp_••••••••3456'

// Stripe keys
maskToken('sk_test_XXXXXXXXXXXXXXXXXXXX');
// → 'sk_test_••••••••XXXX'

// AWS keys
maskToken('AKIAIOSFODNN7EXAMPLE');
// → 'AKIA••••••••MPLE'
```

## 📚 Usage Examples

### Security Presets

Choose from 4 optimized presets for different use cases:

```typescript
import { presets } from '@ekaone/mask-token';

const token = 'sk_test_XXXXXXXXXXXXXXXXXXXX';

// Strict - Maximum security (production logs, compliance)
presets.strict(token);
// → 'sk_test_••••••••••••XXXX'

// Balanced - Good for general use
presets.balanced(token);
// → 'sk_test_XX••••••••XXXX'

// Lenient - More visible (development only)
presets.lenient(token);
// → 'sk_test_XXXX******XXXXXX'

// UI - Optimized for user interfaces
presets.ui(token);
// → 'sk_test_XXXX••••••••XXXX'
```

### Custom Configuration

```typescript
import { maskToken } from '@ekaone/mask-token';

maskToken('secret123', {
  fixedLength: 12,      // Fixed mask length (entropy-safe)
  showHead: 2,          // Show first 2 chars
  showTail: 3,          // Show last 3 chars
  maskChar: '█',        // Custom mask character
});
// → 'se████████████123'
```

### Input Validation

Detect potential mistakes before they become security issues:

```typescript
import { maskToken } from '@ekaone/mask-token';

// Detects placeholder values
maskToken('undefined', { warnIfPlain: true });
// ⚠️ Console warning: "Looks like a placeholder value"
// → '••••••••ned'

// Detects wrong credential types
maskToken('my_password', { warnIfPlain: true });
// ⚠️ Console warning: "Might be a different credential type"
// → '••••••••word'

// Custom validation rules
maskToken(input, {
  warnIfPlain: true,
  validators: {
    minLength: 20,
    noSpaces: true,
    pattern: /^[A-Za-z0-9_-]+$/
  }
});
```

### Custom Token Prefixes

Register your own token formats:

```typescript
import { registerPrefix, maskToken } from '@ekaone/mask-token';

// Register custom prefix
registerPrefix('myapp_', 'MyApp API Key');

// Now it's auto-detected
maskToken('myapp_secret123456789');
// → 'myapp_••••••••6789'
```

### Get Token Metadata

```typescript
import { maskToken } from '@ekaone/mask-token';

const result = maskToken('npm_secret123', { 
  includeMetadata: true 
});

console.log(result);
// {
//   masked: 'npm_••••••••t123',
//   metadata: {
//     type: 'NPM Token',
//     prefix: 'npm_',
//     confidence: 1.0,
//     isLikelyToken: true
//   },
//   validation: {
//     valid: true,
//     warnings: [],
//     riskScore: 0
//   },
//   original: {
//     length: 17,
//     hasPrefix: true
//   }
// }
```

### Batch Processing

```typescript
import { maskToken } from '@ekaone/mask-token';

const tokens = [
  'npm_abc123',
  'ghp_xyz789',
  'sk_test_secret'
];

const masked = tokens.map(t => maskToken(t));
// [
//   'npm_••••••••123',
//   'ghp_••••••••789',
//   'sk_test_••••••ret'
// ]
```

### JWT Tokens

```typescript
import { maskToken } from '@ekaone/mask-token';

const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

maskToken(jwt, { mode: 'jwt' });
// → 'eyJ•••.eyJ•••.doz•••'
```

## 🎯 API Reference

### Main Function

#### `maskToken(token, options?)`

Masks a token with intelligent defaults.

**Parameters:**
- `token` (string): Token to mask
- `options` (MaskOptions, optional): Configuration options

**Returns:** `string | MaskResult`

**Example:**
```typescript
maskToken('npm_secret123');
// → 'npm_••••••••t123'
```

### Options

```typescript
interface MaskOptions {
  // Masking behavior
  fixedLength?: number | boolean;  // Fixed mask length (default: 8)
  showTail?: number;               // Chars to show from end (default: 4)
  showHead?: number;               // Chars to show from start (default: 0)
  maskChar?: string;               // Masking character (default: '•')
  
  // Prefix handling
  preservePrefix?: boolean | string[];  // Auto-detect prefixes (default: true)
  customPrefixes?: Record<string, string>;  // Custom prefix definitions
  
  // Security & validation
  warnIfPlain?: boolean;           // Warn about suspicious inputs (default: false)
  validators?: ValidationRules;    // Custom validation rules
  onWarning?: (result: ValidationResult) => void;  // Warning callback
  
  // Advanced
  mode?: 'auto' | 'jwt' | 'custom';  // Masking mode (default: 'auto')
  segments?: SegmentConfig;        // Segment configuration
  includeMetadata?: boolean;       // Return full result (default: false)
  preset?: 'strict' | 'balanced' | 'lenient' | 'ui';  // Use preset
}
```

### Presets

#### `presets.strict(token)`
Maximum security preset for production environments.

#### `presets.balanced(token)`
Balanced preset for general use.

#### `presets.lenient(token)`
Lenient preset for development (NOT for production).

#### `presets.ui(token)`
UI-optimized preset for user interfaces.

### Utilities

#### `registerPrefix(prefix, description)`
Register a custom token prefix for auto-detection.

```typescript
registerPrefix('myapp_', 'MyApp API Key');
```

#### `detectTokenType(input)`
Detect token type from input string.

```typescript
const metadata = detectTokenType('npm_abc123');
// {
//   type: 'NPM Token',
//   prefix: 'npm_',
//   confidence: 1.0,
//   isLikelyToken: true
// }
```

#### `validateToken(input, rules?)`
Validate input for token-like characteristics.

```typescript
const result = validateToken('undefined', {
  minLength: 20,
  noSpaces: true
});
// {
//   valid: false,
//   warnings: ['Input too short', 'Looks like a placeholder'],
//   riskScore: 80
// }
```

#### `definePreset(config)`
Create a custom reusable preset.

```typescript
const myPreset = definePreset({
  name: 'corporate',
  fixedLength: 16,
  showTail: 6,
  maskChar: '█'
});

myPreset('secret123');
// → '████████████████123'
```

## 🔒 Security Features

### 1. Entropy-Safe Fixed-Length Masking

Prevents length-based enumeration attacks by using a fixed-length mask:

```typescript
// Without fixed length (INSECURE - reveals length)
maskToken('short', { fixedLength: false });      // → '••ort'
maskToken('verylongtoken', { fixedLength: false }); // → '••••••••ken'
// ❌ Attacker knows one token is longer

// With fixed length (SECURE - hides length)
maskToken('short');           // → '••••••••ort'
maskToken('verylongtoken');   // → '••••••••ken'
// ✅ Same mask length, no information leaked
```

### 2. Automated Prefix Preservation

Preserves context without exposing secrets:

```typescript
maskToken('npm_secret123');
// → 'npm_••••••••123'
// ✅ You know it's an NPM token without seeing the secret
```

### 3. Input Validation (Leaked Token Detection)

Catches common mistakes before they become security issues:

```typescript
maskToken('undefined', { warnIfPlain: true });
// ⚠️ Warning: Looks like a placeholder value

maskToken('my password', { warnIfPlain: true });
// ⚠️ Warning: Contains whitespace (tokens typically do not)
```

### 4. Compliance

- **NIST SP 800-122**: Context retention through prefix preservation
- **PCI-DSS**: Head/tail identification (show last 4 digits)
- **OWASP A02**: Entropy hiding via fixed-length masking

## 🎨 Supported Token Types

mask-token automatically detects **43+ token formats** including:

**Version Control & CI/CD**
- NPM (`npm_`)
- GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitLab (`glpat-`, `gldt-`)
- Docker Hub (`dckr_pat_`)

**Payment & Commerce**
- Stripe (`sk_test_`, `sk_live_`, `pk_test_`, `pk_live_`)
- Shopify (`shpat_`, `shpca_`, `shpss_`)

**Communication**
- Slack (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`)
- Twilio (`SK*`, `AC*`)
- SendGrid (`SG.`)

**Cloud Providers**
- AWS (`AKIA`, `ASIA`)
- Google Cloud (`AIza`)
- DigitalOcean (`dop_v1_`)

**AI/ML Services**
- OpenAI (`sk-`, `sk-proj-`)
- Anthropic (`sk-ant-`)

**And many more!** [View full list](./src/presets/registry.ts)

## 🎯 Use Cases

### Production Logs

```typescript
import { presets } from '@ekaone/mask-token';

logger.info('User authenticated', {
  apiKey: presets.strict(apiKey)
});
// Safe to log, compliant with PCI-DSS
```

### Error Messages

```typescript
import { maskToken } from '@ekaone/mask-token';

try {
  await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
} catch (error) {
  throw new Error(`Request failed with token ${maskToken(token)}`);
  // Error message is safe to display/log
}
```

### Settings Pages

```typescript
import { presets } from '@ekaone/mask-token';

function ApiKeyDisplay({ apiKey }) {
  return (
    <div>
      <label>Your API Key</label>
      <input 
        type="text" 
        value={presets.ui(apiKey)} 
        readOnly 
      />
    </div>
  );
}
```

### Documentation

```typescript
import { maskToken } from '@ekaone/mask-token';

const example = maskToken('sk_test_XXXXXXXXXXXXXXXXXXXX');
// Use in documentation without exposing real keys
```

## ⚙️ Configuration

### TypeScript

Full TypeScript support with comprehensive types:

```typescript
import { maskToken, MaskOptions, MaskResult } from '@ekaone/mask-token';

const options: MaskOptions = {
  fixedLength: 8,
  showTail: 4,
  maskChar: '•'
};

const result: string = maskToken('secret', options);
```

### Environment-Specific Presets

```typescript
import { presets } from '@ekaone/mask-token';

const maskFn = process.env.NODE_ENV === 'production'
  ? presets.strict
  : presets.lenient;

console.log(maskFn(apiKey));
```

## 📊 Performance

- **Bundle size**: ~5 KB gzipped (full package)
- **Tree-shakeable**: Import only what you need
- **Zero dependencies**: No supply chain vulnerabilities
- **Fast**: Constant-time operations

```typescript
// Only bundles what you use
import { maskToken } from '@ekaone/mask-token';
// → ~3.8 KB gzipped

import { presets } from '@ekaone/mask-token';
// → ~4.5 KB gzipped
```

## 🔧 Advanced Usage

### Custom Validation

```typescript
import { maskToken } from '@ekaone/mask-token';

maskToken(token, {
  warnIfPlain: true,
  validators: {
    minLength: 32,
    pattern: /^sk_/,
    customCheck: (input) => !input.includes('test')
  },
  onWarning: (result) => {
    // Send to error tracking
    Sentry.captureMessage(`Invalid token: ${result.warnings}`);
  }
});
```

### Custom Segment Masking

```typescript
import { maskToken } from '@ekaone/mask-token';

// Mask UUID-like tokens
maskToken('550e8400-e29b-41d4-a716-446655440000', {
  mode: 'custom',
  segments: {
    delimiter: '-',
    showCharsPerSegment: 2
  }
});
// → '55••••-e2••••-41••••-a7••••-44••••'
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Adding New Token Prefixes

To add support for a new token type, edit [`src/presets/registry.ts`](./src/presets/registry.ts):

```typescript
{
  pattern: 'myservice_',
  name: 'MyService API Token',
  minLength: 32,
  category: 'api',
}
```

## 📝 License

MIT © 2026

## 🙏 Acknowledgments

This library follows security best practices from:
- [NIST SP 800-122](https://csrc.nist.gov/pubs/sp/800/122/final) - Guide to Protecting the Confidentiality of PII
- [PCI-DSS](https://www.pcisecuritystandards.org/) - Payment Card Industry Data Security Standard
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - A02:2021 – Cryptographic Failures

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@ekaone/mask-token)
- [GitHub Repository](https://github.com/ekaone/mask-token)
- [Issue Tracker](https://github.com/ekaone/mask-token/issues)
- [Changelog](./CHANGELOG.md)

## Related Packages

- [@ekaone/mask-card](https://www.npmjs.com/package/@ekaone/mask-card) - Credit card masking library
- [@ekaone/mask-email](https://www.npmjs.com/package/@ekaone/mask-email) - Email address masking library

## 💡 FAQ

### Why mask tokens?

Even though tokens are unique and secure, they can be accidentally exposed through:
- Screenshots shared in Slack/Teams
- Error messages in logs
- Customer support tickets
- Documentation examples
- Public repositories

Masking tokens prevents these accidental exposures while preserving enough context for debugging.

### When should I use which preset?

- **strict**: Production logs, compliance requirements, audit trails
- **balanced**: General application use, internal tools, developer dashboards
- **lenient**: Local development, debugging (never use in production!)
- **ui**: Settings pages, user interfaces, mobile apps

### Is the masked output reversible?

No. Once a token is masked, the original value cannot be recovered. The masking process is one-way and irreversible by design.

### Does this replace proper secret management?

No. This library is for **displaying** tokens safely, not for storing them. Always use proper secret management solutions (environment variables, secret managers, encrypted storage) for storing tokens.
