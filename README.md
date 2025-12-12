# bfx-facs-auth-google

### Example configuration

```
{
  "a0": {
    "google" : {
      "clientId": "legacy-web-client-id",
      "clientSecret": "legacy-web-client-secret",
      "redirectUris": {
        "sso_auth": "https://web.example.com/auth/callback"
      },
      "mobile": {
        "android": {
          "clientId": "android-prod-client-id",
        },
        "ios": {
          "clientId": "ios-prod-client-id",
        }
      }
    },
    "ADM_USERS" : [
      {
        "email": "admL1@bitfinex.com",
        "password": "example123",
        "level": 1
      },
      {
        "email": "admL2@bitfinex.com",
        "password": "example123",
        "level": 2
      },
      {
        "email": "google@bitfinex.com",
        "password": false,
        "level": 0
      }
    ]
  }
}
```

### Selecting the right client
- **Security**: Token `aud` (audience) is the source of truth - `clientKey` is just a hint
- `clientKey` (optional) can be sent by frontend/mobile to indicate which client to use (e.g. `androidProd`)
- The backend validates the Google token's `aud` field and maps it to a configured client ID
- If `clientKey` is provided, it must match the token's `aud` - otherwise request is rejected
- Resolution order: `aud` match → `clientKey` → `webClient` (from root `google.clientId`)
