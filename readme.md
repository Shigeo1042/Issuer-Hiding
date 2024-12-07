# Bobolzらの方式

## 論文情報

- 著者
    - Jan Bobolz
    - Fabian Eidens
    - Stephan Krenn
    - Sebastian Ramacher
    - Kai Samelin
- タイトル: “Issuer-Hiding Attribute-Based Credentials”
- https://eprint.iacr.org/2022/213.pdf

## Groth署名

- $\mathsf{Groth_1}$
    - $\mathsf{Groth_1.ParGen}(1^\lambda): pp:=(\mathbb{G}_1, \mathbb{G}_2, \mathbb{G}_\mathrm{T}, e, p, G, \tilde{G}), e$はペアリング演算, $p$ は素数, $G\in \mathbb{G}_1, \tilde{G}\in \mathbb{G}_2$, ランダム要素 $Y\stackrel{\$}{\leftarrow} \mathbb{G}_1$
    - $\mathsf{Groth_1.KGen}(pp): \mathit{sk}\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast, \mathit{pk} = \tilde{G}^{\mathit{sk}}$
    - $\mathsf{Groth_1.Sign}(pp, \mathit{sk},M):$ ランダムな $r$ を $r\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast$ で選ぶ.    
    $$
    \sigma = (\tilde{R},S,T) = (\tilde{G}^r, (Y\cdot G^{\mathit{sk}})^{1/r}, (Y^{\mathit{sk}}\cdot M)^{1/r})
    $$
    - $\mathsf{Groth_1.Rand}(pp,\sigma):$ ランダムな $r'$ を $r'\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast$ で選ぶ.
        
        $$
        \sigma' = (\tilde{R}',S',T') = (\tilde{R}^{r'}, S^{1/r'}, T^{1/r'})
        $$
        
    - $\mathsf{Groth_1.Verify}(pp,\mathit{pk},\sigma,M):$  check
    
    $$
    e(S,\tilde{R}) = e(Y,\tilde{G})\cdot e(G,\mathit{pk}), e(T,\tilde{R}) = e(Y,\mathit{pk})\cdot e(M,\tilde{G})
    $$
    
- $\mathsf{Groth_2}$
    - $\mathsf{Groth_2.ParGen}(1^\lambda): pp:=(\mathbb{G}_1, \mathbb{G}_2, \mathbb{G}_\mathrm{T}, e, p, G, \tilde{G})$, $\mathit{e}$はペアリング演算, $p$ は素数, $G\in \mathbb{G}_1, \tilde{G}\in \mathbb{G}_2$までは$\mathsf{Groth_1}$と同じもの。 ランダム要素 $\tilde{Y}\stackrel{\$}{\leftarrow} \mathbb{G}_2$
    - $\mathsf{Groth_2.KGen}(pp): \mathit{sk}\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast, \mathit{pk} = G^{\mathit{sk}}$
    - $\mathsf{Groth_2.Sign}(pp, \mathit{sk},M):$ ランダムな $r$ を $r\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast$ で選ぶ.
    
    $$
    \sigma = (R,\tilde{S},\tilde{T}) = (G^r, (\tilde{Y}\cdot \tilde{G}^{\mathit{sk}})^{1/r}, (\tilde{Y}^{\mathit{sk}}\cdot M)^{1/r})
    $$
    
    - $\mathsf{Groth_2.Rand}(pp,\sigma):$ ランダムな $r'$ を $r'\stackrel{\$}{\leftarrow}\mathbb{Z}_p^\ast$ で選ぶ.
        
        $$
        \sigma' = (R',\tilde{S}',\tilde{T}') = (R^{r'}, \tilde{S}^{1/r'}, \tilde{T}^{1/r'})
        $$
        
    - $\mathsf{Groth_2.Verify}(pp,\mathit{pk},\sigma,M):$  check
    
    $$
    e(\tilde{S},R) = e(\tilde{Y},G)\cdot e(\tilde{G},\mathit{pk}), e(\tilde{T},R) = e(\tilde{Y},\mathit{pk})\cdot e(M,G)
    $$
    

## Bobolzらの構成

- メッセージ: $M = (m_1, m_2, \ldots, m_i, \ldots, m_\ell)$
- $\mathsf{Par.Gen}(1^\lambda): pp = (\mathbb{G}_1, \mathbb{G}_2, \mathbb{G}_\mathrm{T}, e, p, G, \tilde{G}, Y, \tilde{Y}, (h_i)_{i = 1}^{\ell})$.  $\mathit{e}$はペアリング演算, $p$ は素数, $G\in \mathbb{G}_1, \tilde{G}\in \mathbb{G}_2$, ランダム要素 $Y, h_i\stackrel{\$}{\leftarrow} \mathbb{G}_1$, $\tilde{Y}\stackrel{\$}{\leftarrow}\mathbb{G}_2$, $\ell$はメッセージ数
- $\mathsf{IKGen}(pp):$ $(\mathit{isk},\mathit{ipk}) \stackrel{\$}{\leftarrow}\mathsf{Groth_1.KGen}(pp)$
- $\mathsf{Issue}(pp,\mathit{isk},M)$: Return $\mathit{cred} \stackrel{\$}{\leftarrow}\mathsf{Groth_1.Sign}(pp,\mathit{isk},\prod_{i=1}^{\ell}h_i^{m_i})$
- $\mathsf{VfCred}(pp, \mathit{cred}, M, \mathit{ipk}):$ Return whatever $\mathsf{Groth_1.Verify}(pp,\mathit{ipk},\mathit{cred},\prod_{i = 1}^{\ell} h_i^{m_i})$ returns.
- $\mathsf{IssueList}(\{\mathit{ipk}_i\}:$  Generate $(\mathit{vsk},\mathit{vpk})\stackrel{\$}{\leftarrow}\mathsf{Groth_2.KGen}(pp)$ and $\sigma_i = (R_i,\tilde{S}_i,\tilde{T}_i)\stackrel{\$}{\leftarrow}\mathsf{Groth_2.Sign}(pp, u, \mathit{ipk}_i)$. Return $\mathit{list} = (\mathit{vpk},\{\mathit{ipk}_i,\sigma_i\})$.
- $\mathsf{VfList}(\mathit{list},\{\mathit{ipk}_i\}):$  Return 1 if $\mathsf{Groth_2.Verify}(pp, \mathit{vpk}, \sigma_i, \mathit{ipk}_i) = 1$ for all $i$. Otherwise, return 0.
- $\mathsf{Present}(pp, \mathit{cred}, \mathit{ipk}, M, \phi, \mathit{list}, \mathsf{ctx}):$  $j$ $j$$\mathit{ipk}_j = \mathit{ipk}$ とする. また,
    - $\mathit{cred}$ と$\sigma_j$を$(\tilde{R},S,T)\stackrel{\$}{\leftarrow}\mathsf{Groth_1.Rand}(pp,\mathit{cred})$ と $(R_j,\tilde{S}_j,\tilde{T}_j)\stackrel{\$}{\leftarrow}\mathsf{Groth_2.Rand}(pp,\sigma_j)$ とランダム化する.
    - ランダムで秘匿する必要のある値$\alpha, \beta, \gamma, \delta\stackrel{\$}{\leftarrow}\mathbb{Z}_p^{\ast}$を選び, 以下の計算をする
        - the blinded credential $(\tilde{R},S',T') := (\tilde{R},S^{1/\alpha}, T^{1/\beta})$ on $\prod_{i=1}^{\ell} h_i^{m_i}$ under the issuer’s key $\mathit{ipk}_j$
        - the issuer’s blinded key $\mathit{ipk}_j' := ipk_j^{1/\gamma}$
        - the blinded list signature $(R_j,\tilde{S}_j,\tilde{T}_j') := (R_j, \tilde{S}_j, \tilde{T}_j^{1/\delta})$ on $\mathit{ipk}_j$ under the verifier’s public key $\mathit{vpk}$
    - Schnorr-styleのproof $\pi$を計算する
    
    $$
    \begin{align*}
    \pi\stackrel{\$}{\leftarrow} \mathrm{NIZK}[(\alpha, \beta, \gamma, \delta, \{m_i\}_{i \notin D}):\\
    \mathsf{Groth_1} \text{ credential check: }& e(Y,\tilde{G}) = e(S', \tilde{R})^{\alpha} \cdot e(G, \mathit{ipk}_j')^{-\gamma} \wedge\\
    \mathsf{Groth_1} \text{ credential check: }& e(\prod_{i \in D} h_i^{m_i}, \tilde{G})^{-1} = e(Y,\mathit{ipk}_j')^\gamma \cdot e(T',\tilde{R})^{-\beta} \cdot e(\prod_{i \notin D} h_i^{m_i}, \tilde{G}) \wedge\\
    \mathsf{Groth_2} \text{ list check: }& e(R_j,\tilde{S}_j) \cdot e(G,\tilde{Y})^{-1} \cdot e(\mathit{vpk}, \tilde{G})^{-1} = 1_{\mathbb{G}_{T}} \wedge\\
    \mathsf{Groth_2} \text{ list check: }& e(\mathit{vpk}, \tilde{Y})^{-1}  =  e(G,\mathit{ipk}_j')^\gamma \cdot e(R_j,\tilde{T}'_j)^{-\delta} \wedge\\
    \text{Attribute check: }& \phi(M) = 1](\mathit{list},\phi,\mathsf{ctx})
    \end{align*}
    $$
    
    - return $\mathit{pt} = ((\tilde{R}, S', T'), \mathit{ipk}_j', (R_j, \tilde{S}_j, \tilde{T}_j'), \pi)$
- $\mathsf{Verify}(\mathit{pt},\mathit{list},\phi):$ Return 1 if and only if $\mathit{pt}$ verifies correctly. Otherwise, return 0.

## 論文内での計測

javaで実装 (https://github.com/cryptimeleon/issuer-hiding-cred)

Table 1. Macbook Pro (i9-9980HK) で BN254 という bilinear group上でのパフォーマンス。他の列はデバイス依存のグループ操作の数（掛け算と自乗計算、指数計算含む）とペアリングの回数

|  | Runtime | $\mathbb{G}_1$ | $\mathbb{G}_2$ | $\mathbb{G}_\mathrm{T}$ | Pairings |
| --- | --- | --- | --- | --- | --- |
| $\mathsf{IssueList}$ (10 issuers) | 14 ms | 3027 | 11448 | 0 | 100 |
| $\mathsf{IssueList}$ (100 issuers) | 115 ms | 27666 | 115430 | 0 | 0 |
| $\mathsf{VfList}$ (10 issuers) | 3 ms | 0 | 0  | 20 | 60 |
| $\mathsf{VfList}$ (100 issuers) | 27 ms | 0 | 0 | 200 | 600 |
| Issue | 2 ms | 1684 | 278 | 0 | 0 |
| Present | 4 ms | 3327 | 1206 | 4 | 7 |
| Verify | 3 ms | 2398 | 0 | 901 | 12 |

Table 2. Number of group elements for the different keys and tokens in Construction 2, where $I$ is the number of issuer keys accepted by a verifier, and $L$ is the number of attributes certified in the credential.

|  | $\mathbb{G}_1$ | $\mathbb{G}_2$ | $\mathbb{G}_\mathrm{T}$ | $\mathbb{Z}_p$ |
| --- | --- | --- | --- | --- |
| Issuer secret key $(\mathit{isk})$ | $-$ | $-$ | $-$ | 1 |
| Issuer public key $(\mathit{ipk})$ | $-$ | $1$ | $-$ | $-$ |
| Credential $(\mathit{cred} )$ | $2$ | $1$ | $-$ | $-$ |
| Presentation list $(\mathit{list})$ | $I + 1$ | $3I$ | $-$ | $-$ |
| Presentation token $(\mathit{pt})$ | $3$ | $4$ | $-$ | $L+5$ |