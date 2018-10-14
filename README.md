# bfx-facs-auth-google

### Example configuration

```
{
  "a0": {
    "google" : {
      "clientId": "test-client-id",
      "clientSecret": "test-client-secret"
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
