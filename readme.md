# Issuer-Hiding Source Codes
## License
Licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)   

## Issuer-Hidingの実装のまとめ

- Issuer-Hiding Attribute-Based Credentials
    - Bobolz et. al.の提案した方式
    - [論文](https://link.springer.com/chapter/10.1007/978-3-030-92548-2_9)
    - [bobolz-credential](./bobolz-credential/): Shigeo1042のRustでの実装（論文を見て1から作成）
    - [筆者らの実装(JAVA)](https://github.com/cryptimeleon/issuer-hiding-cred)
    - ゼロ知識証明部分は[CDL16論文](https://link.springer.com/chapter/10.1007/978-3-319-45572-3_1)を参考に作成
- Protego: Efficient, Revocable and Auditable Anonymous Credentials with Applications to Hyperledger Fabric
    - Connolly et. al.の提案したIssuer-Hiding可能なAnonymous Credentialの方式
    - [論文](https://link.springer.com/chapter/10.1007/978-3-031-22912-1_11)
    - [crypto_docknet](./crypto_docknet/delegatable_credentials/): docknetworkのRustでの実装（[元レポジトリ](https://github.com/docknetwork/crypto/tree/main/delegatable_credentials)）とShigeo1042によるベンチマークの作成が格納されている
    - [筆者らの実装](https://github.com/octaviopk9/indocrypt_protego/tree/main)

- Bobolzらの方式を元にShigeo1042らがBBS署名に適用した方式
    - Shigeo1042らが提案した方式
    - BobolzらのGroth15署名のIssuer-Hidingの方式を応用
    - [issuer-hiding_shigeo](./issuer-hiding_shigeo/): Shigeo1042のRustでの実装
    - BBS署名部分は[mybbs](./bbs/)にShigeo1042がベンチマーク用に実装

- Hidden Issuer Anonymous Credential
    - Boskらが提案したPS署名のIssuer-Hidingの方式
    - [論文](https://hal.science/hal-03789485/)
    - [筆者らの実装](https://gitlab.inria.fr/mgestin/rust_hidden_issuer_signature)

- Compact Issuer-Hiding Authentication, Application to Anonymous Credential
    - Sandersらが提案したPS署名のIssuer-Hidingの方式
    - [論文](https://petsymposium.org/popets/2024/popets-2024-0097.php)
    - [issuer-hiding_sanders](./issuer-hiding_sanders/): Shigeo1042のRustでの実装

- Issuer-Hiding for BBS-Based Anonymous Credentials
    - Katzらが提案したBBS署名のIssuer-Hidingの方式
    - SandersらのPS署名のIssuer-Hidingの方式を応用
    - [論文(e-print)](https://eprint.iacr.org/2025/2080)
    - [issuer-hiding_katz](./issuer-hiding_katz/): Shigeo1042のRustでの実装（Issuer-Hiding部分は論文を見て1から実装）
    - BBS署名部分は[mybbs](./bbs/)にShigeo1042がベンチマーク用に実装