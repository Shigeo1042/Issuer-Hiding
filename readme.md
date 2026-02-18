# Issuer-Hiding Source Codes
## License
Licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)   

## Summary of Issuer-Hiding Implementations

- Issuer-Hiding Attribute-Based Credentials
    - Scheme proposed by Bobolz et al.
    - [paper](https://link.springer.com/chapter/10.1007/978-3-030-92548-2_9)
    - [bobolz-credential](./bobolz-credential/): Rust implementation by the repository owner (built from scratch based on the paper)
    - [Reference Implementation (Java)](https://github.com/cryptimeleon/issuer-hiding-cred)
    - The Zero-Knowledge Proof (ZKP) component was developed with reference to [the CDL16 paper](https://link.springer.com/chapter/10.1007/978-3-319-45572-3_1)

- Protego: Efficient, Revocable and Auditable Anonymous Credentials with Applications to Hyperledger Fabric
    - An anonymous credential scheme supporting Issuer-Hiding proposed by Connolly et al.
    - [paper](https://link.springer.com/chapter/10.1007/978-3-031-22912-1_11)
    - [crypto_docknet](./crypto_docknet/delegatable_credentials/): Contains the Rust implementation by docknetwork（[Original Repository](https://github.com/docknetwork/crypto/tree/main/delegatable_credentials)） and benchmarks created by the repository owner.
    - [Reference Implementation](https://github.com/octaviopk9/indocrypt_protego/tree/main)

- BBS Signature adaptation based on Bobolz et al.
    - Scheme proposed by the repository owner and co-authers.
    - Applies the Issuer-Hiding technique from Bobolz et al.’s Groth15 signatures to BBS signatures.
    - [my_issuer-hiding](./my_issuer-hiding/): Rust implementation by the repository owner.
    - The core BBS signature logic is implemented in [mybbs](./bbs/) for benchmarking purposes.

- Hidden Issuer Anonymous Credential
    - Issuer-Hiding scheme for PS (Pointcheval-Sanders) signatures proposed by Bosk et al.
    - [paper](https://hal.science/hal-03789485/)
    - [Reference Implementation](https://gitlab.inria.fr/mgestin/rust_hidden_issuer_signature)

- Compact Issuer-Hiding Authentication, Application to Anonymous Credential
    - Issuer-Hiding scheme for PS signatures proposed by Sanders and Traoré.
    - [paper](https://petsymposium.org/popets/2024/popets-2024-0097.php)
    - [issuer-hiding_sanders](./issuer-hiding_sanders/): Rust implementation by the repository owner.

- Issuer-Hiding for BBS-Based Anonymous Credentials
    - Issuer-Hiding scheme for BBS signatures proposed by Katz and Sefranek.
    - Applies the Issuer-Hiding method of Sanders and Traoré (for PS signatures) to BBS.
    - [paper (e-print)](https://eprint.iacr.org/2025/2080)
    - [issuer-hiding_katz](./issuer-hiding_katz/): Rust implementation by the repository owner (the Issuer-Hiding logic was implemented from scratch based on the paper).
    - The core BBS signature logic is implemented in [mybbs](./bbs/) for benchmarking purposes.