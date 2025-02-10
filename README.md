# Dynamic Token Status List

Traditional status management solutions, such as status lists or revocation
lists, rely on static entries that allow relying parties to track the status of
presented credentials. However, these approaches have several drawbacks:

- **Privacy concerns**: Static entries enable tracking over time.
- **Inefficiency with short-lived credentials**: Frequent reissuance is
  required.
- **Offline verification issues**: These methods do not work offline unless
  previously cached.

The **dynamic status list** provides a privacy-friendly alternative by using
dynamic identifiers, reducing traceability by relying parties over time.

## Features

- **Privacy with time-based tokens**: Limits the verification window to reduce
  tracking.
- **Flexible cryptographic design**: Does not depend on a specific algorithm to
  function.
- **Supports multiple formats**: Can be used with both **JSON Web Tokens
  (JWTs)** and **CBOR Web Tokens (CWTs)**.
- **Zero-Knowledge Proof-like properties**: The holder can generate a proof
  without revealing the secret, enhancing privacy.

## Privacy with Time-Based Tokens

The dynamic status list is essentially a list of **time-based hashes**. These
hashes are calculated using a **time-based token** and the **credential ID** as
inputs. The secret to generating the time-based token is shared **only** between
the **status manager** and the **holder**.

### Verification Process

- The relying party can verify a credential's status **only when the holder
  presents the time-based token**.
- The verification window is limited to a specific timeframe, preventing
  long-term tracking.
- This approach enhances **privacy and security** by ensuring dynamic,
  time-sensitive status verification.
- The holder can generate a proof that their credential is valid without
  exposing the secret used to generate the proof, making it conceptually similar
  to a **zero-knowledge proof**.

## Status List Containers

The dynamic status list can be managed using different container formats, all of
which utilize **JWTs or CWTs** to store information. The choice of container
does not affect privacy but impacts **resource efficiency and verification
methods**.

### CL (Compact List)

- Values are stored as a **list** for direct matching.
- Simple implementation but **resource-intensive** as the list grows.
- Similar to a Certificate Revocation List (CRL), but instead of publishing
  revoked credentials, a **proof of issuance** is published.
- The wallet must send this proof to the relying party for verification.

### Cascading Bloom Filter (**Deprecated**)

- Values are stored in a **Bloom filter** to improve resource efficiency.
- However, this method introduces **false positives**, which can compromise
  security.
- Testing showed that **revoked credentials could be falsely marked as valid
  within seconds**.
- Due to these security concerns, **this method has been removed** from the
  repository.

---
This project aims to enhance privacy while maintaining efficiency in status
verification. For further details or contributions, please refer to the
repository documentation.

## Benchmarks

The following benchmarks were conducted to evaluate the performance and result:

![Benchmark Results](./benchmark/chart.png)

Each entry is a 32-byte hash. The size is increased because of the base64 encoding to be represented in a JWT. Compressing the hashes has no real impact on the size.

The compression via a bloom filter brings the a higher risk of false positives, so it is not recommended.
