# Client Bureau à distance du portail (IronRDP)

`iron-remote-desktop.js` et `iron-remote-desktop-rdp.js` sont le client web d'IronRDP
(Devolutions, MIT/Apache, voir `LICENSE-ironrdp.txt`), compilé depuis les sources avec un ajout de
Portunia : `ironrdp-portunia.patch`.

- Sources : https://github.com/Devolutions/IronRDP, commit `905c28b3a4e67b15fac274c5d808ef3cef0eb813`
  (29 octobre 2026).
- Ajout : l'extension `performance_flags` (fonction `performanceFlags(n)` du module RDP) choisit les
  effets visuels demandés au serveur Windows (`PerformanceFlags`, MS-RDPBCGR 2.2.1.11.1.1.1). Le
  portail s'en sert pour le choix « Qualité d'affichage ». Les codecs ne changent pas : les
  enregistrements `.rdpcap` restent relus par Portunia.

## Recompiler

```sh
git clone https://github.com/Devolutions/IronRDP.git && cd IronRDP
git checkout 905c28b3a4e67b15fac274c5d808ef3cef0eb813
git apply ../ironrdp-portunia.patch
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
cd crates/ironrdp-web
RUSTFLAGS='-Ctarget-feature=+simd128,+bulk-memory --cfg getrandom_backend="wasm_js" -Copt-level=s -Ccodegen-units=1 -Cllvm-args=-enable-dfa-jump-thread' wasm-pack build --target web
```

Puis, comme `cargo xtask web build` : en tête de `pkg/ironrdp_web.js`, ajouter
`import wasmUrl from './ironrdp_web_bg.wasm?url';` et remplacer
`new URL('ironrdp_web_bg.wasm', import.meta.url)` par `wasmUrl`. Ensuite :

```sh
cd web-client/iron-remote-desktop && npm ci --ignore-scripts && npx vite build
cd ../iron-remote-desktop-rdp && npm ci --ignore-scripts && npx vite build
```

Copier `web-client/iron-remote-desktop/dist/iron-remote-desktop.js` vers `iron-remote-desktop.js` et
`web-client/iron-remote-desktop-rdp/dist/iron-remote-desktop-rdp.js` vers `iron-remote-desktop-rdp.js`.
