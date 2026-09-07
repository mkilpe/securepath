# keygen / sp_keygen

The key material of a deployment. Every process taking part in the public-key handshake
authenticates with a certificate chain that ends in one root public key: the daemons present
theirs in the handshake and the clients present theirs where a server requires it (the key
server lets clients stay anonymous). The library has no built-in root; `sp_keygen` creates one
per deployment and certifies the keys with it. Library target `keygen`
(`infrastructure/keygen/pki.hpp`), executable `sp_keygen`.

## The pki directory

`--pki DIR` names a directory holding

| file | content |
|---|---|
| `root.priv` | root private key; only needed to create the CA, keep it offline |
| `root.pub` | root public key (DER), the trust anchor every process loads with `--root` |
| `ca.priv` | CA private key (ca level 1) that certifies the server and client keys |
| `ca.cert` | the CA's key certificate issued by the root |

The private keys are stored unencrypted with owner-only file permissions (as is the private
data database an identity goes into), so protect the directory. Loading checks that the CA
certificate was issued by the root key and installs the root as the process-wide root public
key.

## Commands

```
sp_keygen --pki DIR --init                    create a new root and CA into DIR
sp_keygen --pki DIR --server DIR2 [--host H]  certified server key into DIR2/private_data.db,
                                              its public half into DIR2/public_key.db
sp_keygen --pki DIR --client FILE             certified client key into the sqlite FILE
                                              (private data and public key stores in one file)
sp_keygen --pki DIR                           print the root and CA key ids
```

`--server` writes the identity a daemon started in `DIR2` picks up through the default
`encrypted_net_base_params` store names. `--host` restricts the certificate to that hostname
and its sub-domains; without it the key is valid for any host. The tool prints the id of the
key it made, which is what peers use to refer to the process. An existing pki or identity is
never overwritten. Logs go to `sp_keygen.log` in the working directory.

## Running the daemons

```
sp_keygen --pki pki --init
sp_keygen --pki pki --server ks
cd ks && key_serverd --root ../pki/root.pub --port 18188
```

Every process loads the root with `--root` (`encrypted_net_base_params::root_public_key_file`,
`crypto::set_root_public_key_from_file()`). A daemon without a root cannot verify any chain, and
one without an installed identity fails its handshake with "no own key or certificate chain".

## Library

`keygen::pki` — `create(suite)`, `load()`, `exists()`, `certify(private_key&, host)` returning
the root → CA → key chain (the key's public half gets the certificate id), accessors for the
keys, the CA chain and the file names. `keygen::install_identity(pki, identity_stores, host)`
generates, certifies and stores an identity (`my_private_key` / `my_certificate_chain` in the
private data database, the public half in the public key database) and refuses when an own key
already exists there. Tests: `test_keygen`.

## Rollover

The root is a single anchor by design (threat model item 7.12): changing it means re-issuing
every certificate. Run `--init` into a new directory, certify every identity again and switch
all processes' `--root` together.
