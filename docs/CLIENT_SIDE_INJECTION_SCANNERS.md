# Client-side Injection Scanners Documentation

## Overview

This document covers the Client-side XPath Injection and Client-side JSON Injection scanners that are part of the Bug Bounty Automation Toolkit. These scanners specifically target DOM-based vulnerabilities in web applications.

## Client-side XPath Injection Scanner

### Description
The Client-side XPath Injection Scanner detects vulnerabilities where user-controlled input is used in client-side XPath operations without proper validation. This includes:

- **DOM-based XPath Injection (CWE-79, CWE-116, CWE-159)**
- **Reflected DOM-based XPath Injection**  
- **Stored DOM-based XPath Injection**

### Vulnerability Types Covered

#### 1. DOM-based XPath Injection (0x00200360 - 2098016)
- **Severity**: Low
- **CWE IDs**: CWE-79, CWE-116, CWE-159
- **Description**: User input from URL fragments or parameters is used in XPath expressions on the client-side

#### 2. Client-side XPath Injection (Reflected DOM-based) (0x00200361 - 2098017)
- **Severity**: Low  
- **CWE IDs**: CWE-79, CWE-116, CWE-159
- **Description**: Server-reflected user input is used in client-side XPath operations

#### 3. Client-side XPath Injection (Stored DOM-based) (0x00200362 - 2098018)
- **Severity**: Low
- **CWE IDs**: CWE-79, CWE-116, CWE-159
- **Description**: Stored user input is retrieved and used in client-side XPath operations

### Detection Methods

1. **JavaScript XPath Pattern Detection**: Identifies JavaScript code that uses XPath functions
2. **Payload Injection**: Tests various XPath injection payloads in URL parameters and fragments
3. **Error Pattern Recognition**: Detects XPath-specific error messages
4. **Context Analysis**: Verifies if payloads appear in JavaScript execution contexts

### JavaScript Patterns Detected
- `document.evaluate()`
- `selectNodes()` and `selectSingleNode()`
- `XPathResult` and `XPathExpression`
- XPath expressions like `//node()`, `@attribute`, etc.

### Configuration Options
```yaml
client_xpath:
  enabled: true
  payload_file: "payloads/client_xpath_payloads.txt"
  test_types: ["dom", "reflected", "stored"]
  confidence_threshold: 0.6
  check_fragments: true
  check_parameters: true
```

### Usage Examples
```bash
# Test for all client-side XPath injection types
python main.py --scan client_xpath --target https://example.com

# Test specific web application with custom config
python main.py --scan client_xpath --target https://webapp.com --config custom.yml

# Include in full scan
python main.py --scan all --target https://example.com
```

## Client-side JSON Injection Scanner

### Description
The Client-side JSON Injection Scanner detects vulnerabilities where user-controlled input is used in client-side JSON operations without proper validation. This includes:

- **DOM-based JSON Injection (CWE-79, CWE-116, CWE-159)**
- **Reflected DOM-based JSON Injection**
- **Stored DOM-based JSON Injection**

### Vulnerability Types Covered

#### 1. DOM-based JSON Injection (0x00200370 - 2098032)
- **Severity**: Low
- **CWE IDs**: CWE-79, CWE-116, CWE-159
- **Description**: User input from URL fragments or parameters is used in JSON parsing/manipulation

#### 2. Client-side JSON Injection (Reflected DOM-based) (0x00200371 - 2098033)
- **Severity**: Low
- **CWE IDs**: CWE-79, CWE-116, CWE-159
- **Description**: Server-reflected user input is used in client-side JSON operations

#### 3. Client-side JSON Injection (Stored DOM-based) (0x00200372 - 2098034)
- **Severity**: Low
- **CWE IDs**: CWE-79, CWE-116
- **Description**: Stored user input is retrieved and used in client-side JSON operations

### Detection Methods

1. **JSON Pattern Detection**: Identifies JavaScript code using JSON.parse(), JSON.stringify(), etc.
2. **Payload Injection**: Tests various JSON-breaking payloads
3. **JSONP Testing**: Detects JSONP callback injection vulnerabilities
4. **Prototype Pollution**: Tests for JavaScript prototype pollution via JSON injection
5. **Structure Breaking**: Verifies if payloads break JSON structure causing errors

### JavaScript Patterns Detected
- `JSON.parse()` and `JSON.stringify()`
- `eval()` with JSON-like structures  
- `$.parseJSON()` and framework-specific JSON parsers
- JSONP callback patterns
- Dynamic JSON construction

### Special Features

#### JSONP Injection Detection
Tests for JSONP callback parameter manipulation:
```javascript
callback=malicious_function
jsonp=alert(1)
cb=eval(atob("YWxlcnQoMSk="))
```

#### Prototype Pollution Detection
Tests for JavaScript prototype pollution:
```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

### Configuration Options
```yaml
client_json:
  enabled: true
  payload_file: "payloads/client_json_payloads.txt"
  test_types: ["dom", "reflected", "stored", "jsonp"]
  confidence_threshold: 0.6
  check_fragments: true
  check_parameters: true
  test_prototype_pollution: true
```

### Usage Examples
```bash
# Test for all client-side JSON injection types
python main.py --scan client_json --target https://example.com

# Test JSONP endpoints specifically
python main.py --scan client_json --target https://api.example.com/jsonp

# Include in full scan
python main.py --scan all --target https://example.com
```

## Payload Files

### Client-side XPath Payloads (`payloads/client_xpath_payloads.txt`)
Contains specialized payloads for DOM-based XPath injection:
- Basic XPath injection patterns
- XPath function injection
- XPath axis manipulation
- Boolean-based blind testing
- URL-encoded and unicode variants

### Client-side JSON Payloads (`payloads/client_json_payloads.txt`)
Contains specialized payloads for DOM-based JSON injection:
- JSON structure breaking payloads
- XSS via JSON injection
- Prototype pollution payloads
- JSONP callback manipulation
- Framework-specific payloads

## Common Attack Scenarios

### XPath Injection Scenarios
1. **Search Functionality**: User search terms used in XPath queries
2. **Data Filtering**: Filter parameters processed by client-side XPath
3. **Dynamic Content**: URL fragments used in XPath document navigation
4. **Form Processing**: Form data used in XPath validation

### JSON Injection Scenarios  
1. **Configuration Injection**: User data merged into JSON config objects
2. **JSONP APIs**: Callback parameters in JSONP endpoints
3. **Dynamic JSON**: User input concatenated into JSON strings
4. **Client Storage**: Data stored and retrieved as JSON in localStorage/sessionStorage

## Remediation Guidelines

### XPath Injection Prevention
1. **Input Validation**: Validate all user input before XPath operations
2. **Parameterized Queries**: Use parameterized XPath expressions when possible
3. **Encoding**: Properly encode special XPath characters
4. **Principle of Least Privilege**: Limit XPath query capabilities

### JSON Injection Prevention
1. **Safe Parsing**: Use safe JSON parsing methods
2. **Input Validation**: Validate data before JSON operations
3. **Avoid eval()**: Never use eval() with user-controlled data
4. **Object.create(null)**: Use for user data objects to prevent prototype pollution
5. **JSONP Security**: Validate callback parameters against whitelists

## Integration with Toolkit

Both scanners are integrated into the main toolkit and can be:
- Run individually using `--scan client_xpath` or `--scan client_json`
- Included in full scans using `--scan all`
- Configured through the main configuration file
- Customized with specific payload files

## Testing and Validation

Comprehensive test suites are provided:
- `tests/test_client_xpath_injection.py`
- `tests/test_client_json_injection.py`

Run tests with:
```bash
python -m pytest tests/test_client_xpath_injection.py
python -m pytest tests/test_client_json_injection.py
```
