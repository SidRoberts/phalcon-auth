Sid\Phalcon\Auth
================

Auth component for Phalcon.

Passwords are created using [`Phalcon\\Security::hash()`](https://github.com/phalcon/cphalcon/blob/phalcon-v2.0.6/phalcon/security.zep#L151) and verified using [`Phalcon\\Security::checkHash()`](https://github.com/phalcon/cphalcon/blob/phalcon-v2.0.6/phalcon/security.zep#L245).



## Installing ##

Install using Composer:

```json
{
    "require": {
        "sidroberts/phalcon-auth": "dev-master"
    }
}
```



## Example ##

### Model ###

```php
namespace Models;

class Users extends \Phalcon\Mvc\Model
{
    public $userID;
    public $username;
    public $password;
    public $emailAddress;
}
```

### DI ###

```php
$di->set(
    "auth",
    function () {
        $auth = new \Sid\Phalcon\Auth\Manager(
            \Models\Users::class,
            "username",
            "password",
            "userID"
        );

        return $auth;
    }
);
```

### Your Code ###

```php
class UserController extends \Phalcon\Mvc\Controller
{
    public function registerAction()
    {
        $username     = $this->request->getPost("username");
        $password     = $this->request->getPost("password");
        $emailAddress = $this->request->getPost("emailAddress");

        $user = $this->auth->createUser($username, $password);

        // Assign other fields here. For example:
        $user->emailAddress = $emailAddress;

        $success = $user->create();

        if ($success) {
            echo "User has been created.";

            // You may want to log in automatically.
            $this->auth->logIn($username, $password);
        } else {
            echo "User has not been created.";
        }
    }

    public function loginAction()
    {
        $username = $this->request->getPost("username");
        $password = $this->request->getPost("password");

        $success = $this->auth->logIn($username, $password);

        if ($success) {
            echo "Login successful.";
        } else {
            echo "Username or password incorrect.";
        }
    }

    public function logoutAction()
    {
        $success = $this->auth->logOut();

        if ($success) {
            echo "Logout successful.";
        } else {
            echo "You're still logged in.";
        }
    }
}
```

## Events ##

| Event Name                | Can stop operation? |
| ------------------------- | ------------------- |
| auth:beforeLogIn          | Yes                 |
| auth:afterLogIn           | No                  |
| auth:beforeLogOut         | Yes                 |
| auth:afterLogOut          | No                  |
| auth:beforeChangePassword | Yes                 |
| auth:afterChangePassword  | No                  |
