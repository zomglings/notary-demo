# Narrative Context and Demo Scenario

This demonstration showcases a practical scenario highlighting the value and security provided by TLSNotary and selective disclosure cryptographic techniques.

## Key Users and Roles

The demo involves the following key parties:

### 1. **Dr. Pierce (the Prover)**

- **Role**: A licensed medical professional who wishes to provide anonymous online consultations.
- **Goal**: Dr. Pierce needs to prove his medical credential (specifically, that he is licensed in California) to potential patients without disclosing any other personal information (e.g., name, address, date of birth).
- **Action**: Uses the Prover UI to construct an HTTPS request to a trusted credentialing service to obtain his credential data securely. He then selectively discloses only the state of licensing ("CA"), generating a cryptographic proof with TLSNotary.

### 2. **Dave (the Verifier)**

- **Role**: A potential patient seeking affordable medical consultation online, who must ensure the anonymous doctor he consults with is credentialed appropriately.
- **Goal**: Dave wants to verify that Dr. Pierce holds a valid medical license in California without needing to see other sensitive details about Dr. Pierce.
- **Action**: Receives a UUID from Dr. Pierce, accesses the Verifier UI, retrieves the corresponding notarized proof, and cryptographically verifies that the response is authentic and that Dr. Pierce is licensed in California.

## External Credentialing Service (ACME)

- **Role**: A trusted third-party credentialing agency that provides official credential data (e.g., doctor's licensing status, state of license, expiration date) through a standard HTTPS API.
- **Scenario**: In this demo, ACME is represented by an external HTTPS endpoint, accessed securely by the TLSNotary protocol. The responses from ACME are cryptographically notarized to guarantee authenticity.

## How These Roles Interact in the Demo

1. **Dr. Pierce** securely retrieves his credential information from the **ACME** API using the Prover server. He uses TLSNotary to cryptographically notarize and selectively disclose only the relevant licensing state (CA). A proof is generated and stored on the Notary/Verifier server, identified by a unique UUID.

2. **Dr. Pierce** independently shares the UUID with **Dave** (e.g., via email, messaging, or another communication channel).

3. **Dave** uses the Verifier UI, inputs the UUID, retrieves the stored notarized proof, and independently verifies its cryptographic validity and authenticity.

This narrative demonstrates:

- **Privacy**: Sensitive information about Dr. Pierce remains confidential.
- **Security and Trust**: Dave receives cryptographic proof directly attested by the trusted credentialing service (ACME).
- **Ease of Verification**: Clear and easy verification workflow, requiring only the provided UUID.

