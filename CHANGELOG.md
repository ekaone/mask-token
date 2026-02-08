# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-06

### 🎉 Initial Release

First stable release of mask-token - a professional-grade token masking library with NIST/PCI-DSS/OWASP compliance.

### ✨ Features

#### Core Functionality
- **Intelligent Token Masking**: Auto-detects and masks 43+ token types including NPM, GitHub, Stripe, AWS, OpenAI, and more
- **Security-First Defaults**: Fixed-length masking prevents length-based enumeration attacks (OWASP A02 compliance)
- **Prefix Preservation**: Automatically preserves token prefixes for context without exposing secrets (NIST SP 800-122 compliance)
- **Configurable Visibility**: Control exactly which parts of tokens are visible (head/tail configuration per PCI-DSS)

#### Security Presets
- **Strict Preset**: Maximum security for production logs and compliance requirements
- **Balanced Preset**: Good balance between security and usability for general use
- **Lenient Preset**: More visible masking for development and debugging
- **UI Preset**: Optimized for user interface display with symmetric visibility

#### Validation & Safety
- **Input Validation**: Detects and warns about placeholder values, wrong credential types, and suspicious inputs
- **Risk Scoring**: Assigns risk scores (0-100) to inputs based on multiple heuristics
- **Batch Validation**: Validate multiple tokens at once with summary statistics
- **Custom Validators**: Define your own validation rules and warning handlers

#### Extensibility
- **Custom Prefixes**: Register your own token formats for auto-detection
- **Custom Presets**: Create reusable masking configurations
- **Custom Mask Characters**: Use any character or string for masking
- **JWT Mode**: Special handling for JWT tokens (header.payload.signature)
- **Custom Segment Masking**: Mask tokens with custom delimiters

#### Developer Experience
- **TypeScript Support**: Full type safety with comprehensive TypeScript definitions
- **Zero Dependencies**: No external dependencies for maximum security and minimal bundle size
- **Tree-Shakeable**: ESM exports for optimal bundle size (~3.8-5.2 KB gzipped)
- **Comprehensive JSDoc**: 100% documentation coverage with examples
- **Intuitive API**: Clean, predictable API design

### 📦 Supported Token Types

#### Version Control & CI/CD (11 types)
- NPM tokens (`npm_`)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitLab tokens (`glpat-`, `gldt-`)
- Docker Hub tokens (`dckr_pat_`)
- Vercel tokens (`vercel_*`)
- Netlify tokens (`nf*`)

#### Payment & Commerce (7 types)
- Stripe keys (`sk_test_`, `sk_live_`, `pk_test_`, `pk_live_`, `rk_test_`, `rk_live_`)
- Shopify tokens (`shpat_`, `shpca_`, `shpss_`)
- Twilio SIDs (`AC*`)

#### Communication (7 types)
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xapp-`)
- Twilio API keys (`SK*`)
- SendGrid API keys (`SG.`)

#### Cloud Providers (5 types)
- AWS keys (`AKIA`, `ASIA`)
- Google Cloud keys (`AIza`)
- DigitalOcean tokens (`dop_v1_`)
- Heroku API keys

#### AI/ML Services (3 types)
- OpenAI keys (`sk-`, `sk-proj-`)
- Anthropic keys (`sk-ant-`)

#### Generic Patterns (10 types)
- Generic API keys (`api_key_*`, `apikey-*`)
- Generic tokens (`token_*`, `token-*`)
- Generic secrets (`secret_*`, `secret-*`)
- Generic prefixed tokens (`[a-z]{2,6}_`)

### 🔒 Security Compliance

- **NIST SP 800-122**: Context retention through prefix preservation
- **PCI-DSS**: Head/tail identification (show last 4 digits standard)
- **OWASP A02:2021**: Entropy hiding via fixed-length masking
- **Zero Dependencies**: No supply chain vulnerabilities
- **Constant-Time Operations**: Performance optimized for security

### 📊 Performance

- **Bundle Size**: ~5 KB gzipped (full package)
- **Tree-Shaken**: ~3.8 KB for basic usage
- **Build Time**: <100ms with esbuild/tsup
- **Zero Runtime Dependencies**: No external packages

### 🎯 API Highlights

```typescript
// Basic usage
maskToken('npm_a1b2c3d4e5f6g7h8i9j0')
// → 'npm_••••••••i9j0'

// Security presets
presets.strict(token)
presets.balanced(token)
presets.lenient(token)
presets.ui(token)

// Custom configuration
maskToken(token, {
  fixedLength: 12,
  showTail: 4,
  maskChar: '█'
})

// Validation
maskToken(input, { warnIfPlain: true })

// Custom prefixes
registerPrefix('myapp_', 'MyApp API Key')

// Metadata
maskToken(token, { includeMetadata: true })
```

### 📝 Documentation

- Comprehensive README with usage examples
- Full API reference with TypeScript types
- Security best practices guide
- 40+ code examples
- FAQ section

### 🏗️ Infrastructure

- **Build System**: tsup with terser minification
- **Type Checking**: TypeScript 5.0+
- **Package Format**: ESM + CommonJS + UMD
- **Source Maps**: Available for debugging

### 🎓 Examples

- Basic masking examples (Planned)
- Preset usage examples (Planned)
- Custom configuration examples (Planned)
- Validation examples (Planned)
- Batch processing examples (Planned)
- JWT masking examples (Planned)
- React component examples (Planned)

---

## [Unreleased]

### Planned for v1.1.0
- [ ] Full metadata return option (detailed token information)
- [ ] Additional token format support (Azure, IBM Cloud, etc.)
- [ ] Performance benchmarks and constant-time verification
- [ ] Browser-specific optimizations

### Planned for v1.2.0
- [ ] Advanced JWT parsing and validation
- [ ] Database connection string masking mode
- [ ] Email address masking mode
- [ ] Credit card number masking mode

### Planned for v2.0.0
- [ ] React component library (`@mask-token/react`)
- [ ] Vue component library (`@mask-token/vue`)
- [ ] CLI tool for masking in scripts
- [ ] Audit logging integration

---

## Version History

### Versioning Strategy

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Release Notes

#### v1.0.0 - Initial Release (2024-02-05)
- First stable release
- All 9 core features implemented
- 43+ token types supported
- Production-ready quality
- Full TypeScript support
- Zero dependencies
- Comprehensive documentation

---

## Migration Guides

### Migrating to v1.0.0

This is the first release, so no migration needed. Welcome! 🎉

### Future Migration Guides

Migration guides for future breaking changes will be documented here.

---

## Contributors

### v1.0.0 Contributors

- **Author**: Eka Prasetia
- **Contributors**: None

### How to Contribute

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

---

## Links

- [NPM Package](https://www.npmjs.com/package/@ekaone/mask-token)
- [GitHub Repository](https://github.com/ekaone/mask-token)
- [Documentation](https://github.com/ekaone/mask-token#readme)
- [Issue Tracker](https://github.com/ekaone/mask-token/issues)
