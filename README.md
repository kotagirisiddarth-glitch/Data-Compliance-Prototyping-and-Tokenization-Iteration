# Data Vault — PII Tokenization Prototype

An experimental, Python-based data vault designed to explore secure storage, tenant-scoped tokenization, and audit logging for personally identifiable information (PII).

The project explores how sensitive data can be replaced with opaque tokens, allowing applications to reference sensitive records without directly exposing the underlying information.

**Status:** Early-stage prototype. Not production-ready.

## Features

* **Data tokenization:** Replaces sensitive input with randomly generated tokens.
* **Data detokenization:** Retrieves the original data associated with a valid token.
* **Tenant separation:** Scopes token records and derived encryption keys to individual tenants.
* **Audit logging:** Records tokenization and detokenization attempts, including successes and failures.
* **Hash-chained audit logs:** Links audit records using SHA-256 hashes to provide basic tamper evidence.
* **Environment-based secrets:** Loads the master secret from an environment variable rather than hardcoding it.

## How It Works

1. An application submits sensitive data and a tenant identifier.
2. The vault generates a token and stores the associated encrypted data.
3. The application receives the token instead of the original data.
4. Authorized applications can retrieve the original data through the detokenization function.
5. Operations are recorded in an audit ledger.

## Technology

* Python
* SQLite
* Python standard library
* SHA-256 hashing
* Environment-based secret configuration

## Current Limitations

This is a learning and research prototype, not a production security product.

* The current encryption implementation uses a custom XOR-based construction and is not secure for protecting real customer data.
* Production-grade authenticated encryption, such as AES-256-GCM, has not yet been implemented.
* Authentication, authorization, and production-grade tenant isolation are not yet implemented.
* Audit hash chaining is tamper-evident but does not guarantee immutability against an attacker with direct database access.
* The prototype has not undergone independent security audits, penetration testing, or compliance certification.

**Do not use this software to store, process, or protect real personal or confidential information.**

## Roadmap

* Implement authenticated encryption using established cryptographic libraries.
* Introduce secure authentication and fine-grained access controls.
* Strengthen tenant isolation and key management.
* Improve audit integrity and verification.
* Develop automated security and reliability tests.
* Explore a production-ready API and developer SDK.

## Motivation

This project is an independent exploration of privacy engineering, data tokenization, and secure infrastructure, with the long-term goal of developing tools that help organizations reduce unnecessary exposure of sensitive data.

The project is under active development. Features, architecture, and implementation may change substantially as research and testing progress.

## License

License to be determined.
