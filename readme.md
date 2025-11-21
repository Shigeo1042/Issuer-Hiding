# readme
Issuer-Hidingの実装のまとめ

- [bobolz-credential](./bobolz-credential/): Bobolz et. al.の提案したIssuer-HidingのRustでの実装（論文を見て1から作成）   
    - [論文](https://link.springer.com/chapter/10.1007/978-3-030-92548-2_9)
    - [筆者らの実装(JAVA)](https://github.com/cryptimeleon/issuer-hiding-cred)
    - ゼロ知識証明部分は[CDL16論文](https://link.springer.com/chapter/10.1007/978-3-319-45572-3_1)を参考に作成
- [crypto_docknet](./crypto_docknet/delegatable_credentials/): Connolly et. al.の提案したIssuer-Hiding可能なAnonymous CredentialのRustでの実装（[docknetwork](https://github.com/docknetwork/crypto/tree/main/delegatable_credentials)が作成）
    - [論文](https://link.springer.com/chapter/10.1007/978-3-031-22912-1_11)
    - [筆者らの実装](https://github.com/octaviopk9/indocrypt_protego/tree/main)