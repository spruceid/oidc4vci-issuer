# OIDC4VCI Demo Issuer

This is an example issuer built with [`rocket`][] and [`oidc4vci-rs`][].

## Endpoints and support

Credential types supported:
  - [x] JWT
  - [ ] JSONLD

Endpoints available:

- `GET /`: to access a pre-authorized code in QRCode or link format, no `pin` support.
- `POST /issuer/preauth?<query..>`: to obtain a pre-authorized code with a specific `type`, `pin` and `user_id`.

- `GET /.well-known/openid-configuration`: to obtain the OIDC configuration.
- `GET /jwks`: to obtain JWKs used by the server.

- `POST /token`: to exchange the pre-authorized code by an access token.
- `POST /credential`: to issue a credential, requires `Authorization` provided by the previous step.

## Planned improvements

- Add JSONLD support;
- Add more configuration options;
  - Supported credential types;
  - Access token expiration time;
- External credential provider to easily change the hard-coded `OpenBadgeCredential`;

## Running

### `.env`

A `.env` file must be created with the following variables:

```bash
ISSUER=http://localhost:9000
JWK='{"kty":"OKP","crv":"Ed25519","x":"","d":""}'
```

The `ISSUER` will be used to fill the `oidc-configuration` endpoint and
inside the credential in the `.issuer.url` field.

The `JWK` will be used to create a DID and sign the credentials.

### `docker-compose`

The `docker-compose` file can be used to run the required Redis instance.

If you want to point to a different instance of Redis, you can add the 
URL to the following variable in the `.env` file:

```bash
REDIS_URL=redis://127.0.0.1/
```

### Rust nightly

The `rust-toolchain.toml` file is configured to use Rust `nightly`.

If that doesn't work, you can add the override manually with:

```bash
rustup override set nightly
```

### `Rocket.toml`

In the `Rocket.toml`, you can change the port that the server will use as shown below:

```toml
[debug]
port = 8080
```

For more information on other server options provided by `Rocket` please refer to its documentation.

[`rocket`]: https://rocket.rs/
[`oidc4vci-rs`]: https://github.com/spruceid/oidc4vci-rs
