# Receive proof of the required conditions without collecting a licence copy

ToppyMicroServices / October 4, 2026

Share only what the check needs. ToppyMicroServices has published a zero-knowledge proof demonstration to help reduce the information people share and businesses retain. Using fictional credentials, it checks an ordinary-car driving entitlement and an expiry date on or after the intended service date, without disclosing a name, address or licence number.[^1]

## A question raised by a car-sharing data breach

On September 29, 2026, Park24 reported that identity-document information, including driving-licence images, had leaked for about 1.6 million Times Car accounts. [Park24 announcement](https://www.park24.co.jp/news/2026/09/20260929-1.html)

Alongside protecting the data a business holds, there is another opportunity: reducing what it collects. Toppy proposes starting with the identity-checking process itself.

## Collect less information at the condition-checking step

For a step that checks an expiry condition, a service can receive proof that the condition is met instead of an entire image containing a name and address. In the demonstration, the holder keeps a credential signed by a trusted issuer and generates a proof from it. The verifier checks the proof against the issuer's signature.

People can complete that check without sharing unrelated personal details. Businesses can explore a design that narrows the information they receive and the records they need to store and protect.

## Practical recommendations for retention and management

Toppy recommends reviewing everyday data management alongside the technology. Organisations can begin with these steps in their current systems.

- **Record why data is kept and for how long.** Treat document images, check results and contract information separately. Record their purpose, location, responsible owner and retention period. Where legal duties or accident and dispute handling require retention, record that reason too.
- **Choose the records each process needs.** Consider whether an entire image is necessary, or whether a record of the check's time, conditions and result meets the purpose. Proofs and usage histories also need a defined purpose and retention period.
- **Limit who can access data and how.** Consider role-based access, multi-factor authentication for administrators, encryption in transit and at rest, and controlled access to keys. Avoid unnecessary copies of identity documents in email, support records and logs.
- **Remove data when its retention reason ends.** Define a deletion process that covers processors, copies and backup expiry. Decide how deleted records will be handled after a restore. During an incident investigation, preserve necessary evidence before deciding what to delete.

Japan's Personal Information Protection Commission guidelines address purpose-specific retention, security measures and efforts to erase personal data when it is no longer needed. Specific periods and retention duties depend on the business and records involved. [PPC general guidelines, in Japanese](https://www.ppc.go.jp/personalinfo/legal/guidelines_tsusoku/), [PPC security FAQ, in Japanese](https://www.ppc.go.jp/all_faq_index/faq1-q10-7/)

Deployment planning also needs clear responsibilities for credentials and devices held by users, original information checked by issuers, and verification histories kept by businesses.

## From a public demonstration to deployment planning

The public demonstration uses fictional credentials. It implements proof generation, verification and replay rejection, and passed all 46 tests on macOS and Linux. The code and reproduction steps let readers inspect what a verifier receives and how the checks work.

A car-sharing deployment needs integration with real licences, person authentication, and suspension and cancellation checks, alongside contractual and insurance requirements. Toppy offers this demonstration as a starting point for collecting less personal information while preserving the checks a service needs.

[Source and reproduction steps](https://github.com/ToppyMicroServices/zk-license-demo) · [Validation record](https://github.com/ToppyMicroServices/zk-license-demo/blob/main/docs/validation.md)

For affected users, check notices through the official site or app you normally use rather than resubmitting personal information through links in unexpected email or SMS. Park24 also warns about impersonation and requests for passwords, authentication codes or payment-card information. [Park24 warning](https://www.park24.co.jp/news/2026/09/20260929-1.html)

[^1]: This demonstration uses [AnonCreds / anoncreds-rs](https://github.com/anoncreds/anoncreds-rs) for its cryptographic operations. The referenced [AnonCreds specification](https://anoncreds.github.io/anoncreds-spec/) is published under the [Community Specification License 1.0](https://github.com/CommunitySpecification/1.0).
