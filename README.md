## API

### /signup

Signup has two stages, the first sends an email to the specified email
with the signup token. In stage 2, upon receiving the token, the user
is finally activated and can use the shapass normally.

The field `password_reset_token` is used as the signup token aswell.

- Request body example `Stage 1`:

```json
{
    "email":"example@shapass.com",
    "password":"example123"
}
```

- Example query, `Stage 2`:

```
http://shapass.com/api/confirmation?email=example@shapass.com?token=randomtoken1234
```

### /login

- Request body example

```json
{
    "email":"example@shapass.com",
    "password":"example123"
}
```

### /list

- Request body example using token
```json
{
    "token": "login-token-here"
}
```

- Request body example (fields `email` and `password` directly)

```json
{
    "email": "example@shapass.com",
    "password": "example123"
}
```

### /create

Metadata field is optional and must be a valid JSON string or empty.

Supported algorithms:

    sha256-str
    sha256-bin
    sha256-alphanum

- Request body example (length must be numeric!)

```json
{
    "token": "login-token-here",
    "name": "service name",
    "length": 32,
    "suffix": "optional suffix",
    "prefix": "optional prefix",
    "algorithm": "sha256-str",
    "metadata": "{}"
}
```

### /delete

- Request body example

```json
{
    "token": "login-token-here",
    "name": "service to be deleted"
}
```

### /whoami

- Request body example

```json
{
    "token": "login-token-here"
}
```

### /logout

- Request body example

```json
{
    "token": "login-token-here"
}
```

### /deleteaccount

- Request body example

```json
{
    "email": "example@shapass.com",
    "password": "example123"
}
```

### /resetpassword

- Request body example

```json
{
    "email": "example@shapass.com",
    "token": "reset-pw-token-here",
    "newpassword": "new password"
}
```

### /loginlist

The field `all` is optional and indicates to list all logins, including expired ones

- Request body example

```json
{
    "token": "reset-pw-token-here",
    "all":true
}
```

### /loginexpire

The guids for this call are returned by the `/loginlist` API.
All the logins passed to this API call will be deleted.

- Request body example

```json
{
    "token": "reset-pw-token-here",
    "guids": ["guid-for-login1", "guid-for-login2"]
}
```