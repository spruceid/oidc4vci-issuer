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

## Example Usage

The following commented bash script is an example of the format and calls made to this issuer.

```bash
# Change URL according to the server you're testing with
url=http://localhost:9000

# If `uuidgen` is not present in your environment, just substitute by a hardcoded value
preauth=$(curl -s -X POST $url/issuer/preauth\?type\=OpenBadgeCredential\&user_id\=$\(uuidgen\))

# This requires `jq` to extract the `access_token` value from the JSON, could be done manually or in other ways
access_token=$(curl -s -X POST $url/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=$preauth"\
  | jq -r '.access_token')

# Replace `proof.jwt` to one generated by your client.
# In this example, the `jwt` uses `did:key:z6MkwEGcHQYdp8dfiM34VSnEdVRMF9TNRECnhvbRHPCBqQr9`
# has a `http://localhost:9000` audience and a one year duration to facilitate testing.
# THEY ARE NOT INTENDED AS EXAMPLE PRODUCTION VALUES
# `type` and `format` might differ if working with other issuers.
# Only `jwt` is supported for `proof.proof_type` at the moment.
credential_request=$(cat <<EOF
{
	"type": "OpenBadgeCredential",
	"format": "ldp_vc",
	"proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3dFR2NIUVlkcDhkZmlNMzRWU25FZFZSTUY5VE5SRUNuaHZiUkhQQ0JxUXI5In0.eyJpc3MiOiJjb20uc3BydWNlaWQuY3JlZGlibGUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJpYXQiOiIyMDIyLTEwLTIwVDE5OjA5OjEwLjcyMjM0NFoiLCJleHAiOiIyMDIzLTEwLTE5VDE5OjA5OjEwLjcyMTcwMFoiLCJqdGkiOiJHc1RFUkZWNEhkTFRGRUE4NWJxZ2FEbzl1WEFrVnJxViJ9.hMqRNt3Ld54FpwN_SmLd6E0wGUZ3-LOaoMWMuVcvZidrZtUGxTt2WsP0jQ0KbqOWruCl0vqD7jTiVJUCyMnZCQ"
  }
}
EOF
)

curl -X POST $url/credential \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $access_token" \
  -d "$credential_request"
```

[`rocket`]: https://rocket.rs/
[`oidc4vci-rs`]: https://github.com/spruceid/oidc4vci-rs
