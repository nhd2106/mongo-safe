# SafeMongo

A Visual Studio Code extension that identifies MongoDB security vulnerabilities in your code with direct links to official MongoDB documentation.

## Features

- **Real-time Security Scanning**: Automatically analyzes JavaScript and TypeScript files as you type
- **Severity Indicators**: Visual icons (🛑 ⚠️ ℹ️) show the severity level of each detected issue
- **Documentation Links**: Direct links to official MongoDB security documentation for each warning
- **Detailed Explanations**: Provides comprehensive information about each vulnerability
- **Actionable Fixes**: Suggests secure alternatives to fix identified issues
- **Multi-language Support**: Works with JavaScript, TypeScript, and their React variants

## Security Issues Detected

SafeMongo identifies 30+ MongoDB security vulnerabilities, including:

### NoSQL Injection

- String concatenation in queries
- Unvalidated user input
- $where/$expr operator misuse
- Template string injection
- Object spread injection
- Regex injection

### Data Exposure

- Unconstrained queries
- Insecure projections
- Mass assignment vulnerabilities
- Sensitive field exposure

### Authentication Bypasses

- Insecure operator usage (like $ne)
- Unvalidated MongoDB ObjectId

### Denial of Service

- Uncontrolled limit/skip values
- Sort injection vulnerabilities
- Insecure text indexing

### Error Handling & Transactions

- Missing error handling
- Unhandled promise rejections
- Transaction without proper error handling

## Usage

1. Install the extension from VS Code Marketplace
2. Open any JavaScript/TypeScript file containing MongoDB queries
3. The extension will automatically scan for security issues
4. Hover over highlighted issues to see descriptions and MongoDB documentation links
5. Click on the warning code to open the MongoDB documentation in your browser
6. For more details, click on "Show details about this MongoDB security issue"

## Publishing the Extension

To publish this extension to the Visual Studio Code Marketplace:

1. **Create a publisher account**:

   - Visit [Visual Studio Marketplace](https://marketplace.visualstudio.com/manage)
   - Sign in with a Microsoft account

2. **Install vsce (Visual Studio Code Extensions)**:

   ```bash
   npm install -g vsce
   ```

3. **Update your publisher name**:

   - Replace "your-publisher-name" in package.json with your actual publisher name

4. **Create a logo**:

   - Create a 128x128 PNG logo file
   - Save it as `images/logo.png`

5. **Package the extension**:

   ```bash
   vsce package
   ```

6. **Publish the extension**:
   ```bash
   vsce publish
   ```

## Requirements

- Visual Studio Code 1.60.0 or newer

## License

ISC

---

Write safer MongoDB code with SafeMongo!
