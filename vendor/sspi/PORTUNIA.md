# sspi 0.23.1, retouché pour Portunia Gate

Copie de la bibliothèque `sspi` 0.23.1 (Devolutions, MIT/Apache-2.0, crates.io), utilisée par
`[patch.crates-io]` dans `Cargo.toml` de la Gate.

## Retouche

`src/negotiate/mod.rs` : `set_server_identity_lookup` et, dans `Negotiate::set_auth_identity`,
un appel à cette recherche quand l'utilisateur n'est pas dans la liste `auth_data` donnée à la
création du serveur.

**Pourquoi** : l'entrée RDP sans Portunia (`src/rdplogin.rs`) joue le serveur NLA face à mstsc,
qui parle SPNEGO. Le serveur SPNEGO de sspi exige la liste des identités dès le premier message,
alors que l'identifiant (« compte%serveur%code ») n'arrive qu'au troisième. En NTLM nu, sspi
demande déjà l'identité au `CredentialsProxy` au bon moment : la retouche donne la même chose
en SPNEGO. Sans recherche réglée, le comportement est celui d'origine.

## Mettre à jour

Copier la nouvelle version depuis `~/.cargo/registry/src/*/sspi-X.Y.Z`, refaire la retouche,
vérifier `cargo test rdplogin` (test NLA en NTLM nu et en SPNEGO).
