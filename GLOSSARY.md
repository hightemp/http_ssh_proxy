# HTTP SSH Proxy

An HTTP proxy that carries traffic through an SSH tunnel to a remote server. This glossary covers the identities involved in establishing that tunnel.

## Language

**Host key**:
The key pair with which the SSH server proves that it is the intended server.
_Avoid_: Server key, known_hosts key

**Client key**:
The private key with which the proxy proves the identity of the SSH user to the server. It is unrelated to the host key, and neither one's type implies the other's.
_Avoid_: SSH key, private key, identity

**Host key verifier**:
The trusted reference for the host key: either a known_hosts file or a pinned fingerprint. Exactly one is configured.
_Avoid_: Host key check, trust store

**Default client key**:
A client key found under a standard name in the user's SSH directory, used when no client key and no password are configured.
_Avoid_: Auto key, discovered key
