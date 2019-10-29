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

### /save

Sends data to be saved related to a logged in user.

- Request body example

```json
{
    "token": "login-token-here",
    "data": "{'iv':[1, 2, ..., 15], 'data':'encrypted-data-here'}"
}
```

### /load

Loads the encrypted user data from the database.

```json
{
    "token": "login-token-here",
}
```

## Error Codes

The API returns the following error codes

```go
    // No errors occurred
    0  => CodeOK

    // An unknown error occurred (database issue mostly)
    1  => CodeInternalError

    // The API call requires the user to be logged in and
    // the user is not.
    2  => CodeNotLoggedIn

    // Incorrect information for login was provided.
    3  => CodeIncorrectLoginInfo

    // Some of the fields required for signup were not
    // provided
    4  => CodeIncorrectSignupInfo

    // The API call requires an activated user, but
    // the user info provided is from a user not yet
    // confirmed by email.
    // This error code should probably not be external.
    5  => CodeUserNotActivated

    // User does not exist in the database.
    // This should never be raised, since the user
    // must be logged in already for an API call
    // to try to access data from them.
    6  => CodeUserDoesNotExist

    // This error is raised when trying to delete a rule 
    // that doesn't exist.
    7  => CodeRuleDoesNotExist

    // This error is raised if the JSON input is not
    // valid JSON, or when not all fields required for
    // the called API call were provided.
    8  => CodeInvalidInput

    // This error is raised when the token provided
    // for the API call is not valid.
    9  => CodeInvalidToken

    // This error is raised when the email service
    // failed to send an email. User must try later.
    10 => CodeCouldNotSendEmail

    // An invalid algorithm was sent (i.e. sha233-bin)
    11 => CodeInvalidAlgorithm

    // The password recovery system can only be
    // issued again after some time (30m by default).
    // This error is caused by trying to reset the
    // password again before this period.
    12 => CodeResetPasswordDelay

    // An API request was received with a method
    // different from POST.
    13 => CodeInvalidMethod
```