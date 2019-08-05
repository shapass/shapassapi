## API

### /signup

- Request body example

```json
{
    "email":"example@shapass.com",
    "password":"example123"
}
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

- Request body example (length must be numeric!)

```json
{
    "token": "login-token-here",
    "name": "service name",
	"length": 32,
	"suffix": "optional suffix",
	"prefix": "optional prefix"
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