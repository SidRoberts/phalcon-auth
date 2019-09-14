<?php

namespace Sid\Phalcon\Auth;

use Phalcon\Di\Injectable;
use Phalcon\DiInterface;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Events\ManagerInterface as EventsManagerInterface;
use Phalcon\Mvc\ModelInterface;

class Manager extends Injectable implements EventsAwareInterface
{
    /**
     * @var EventsManagerInterface
     */
    protected $eventsManager;

    /**
     * @var string
     */
    protected $modelName;

    /**
     * @var string
     */
    protected $usernameField;

    /**
     * @var string
     */
    protected $passwordField;

    /**
     * @var string
     */
    protected $userIdField;



    /**
     * @throws Exception
     */
    public function __construct(string $modelName, string $usernameField, string $passwordField, string $userIdField)
    {
        $di = $this->getDI();

        if (!($di instanceof DiInterface)) {
            throw new Exception(
                "A dependency injection object is required to access internal services"
            );
        }



        $this->modelName     = $modelName;
        $this->usernameField = $usernameField;
        $this->passwordField = $passwordField;
        $this->userIdField   = $userIdField;
    }



    /**
     * @return EventsManagerInterface
     */
    public function getEventsManager()
    {
        return $this->eventsManager;
    }

    public function setEventsManager(EventsManagerInterface $eventsManager)
    {
        $this->eventsManager = $eventsManager;
    }



    public function logIn(string $username, string $password) : bool
    {
        $eventsManager = $this->getEventsManager();

        if ($eventsManager instanceof EventsManagerInterface) {
            if ($eventsManager->fire("auth:beforeLogIn", $this) === false) {
                return false;
            }
        }

        if ($this->isLoggedIn()) {
            return true;
        }

        $user = $this->getUserFromCredentials($username, $password);

        if (!$user) {
            return false;
        }

        $userID = $this->getUserIdFromUser($user);

        $di = $this->getDI();

        $session = $di->getShared("session");

        $session->set(
            "auth_userID",
            $userID
        );

        if ($eventsManager instanceof EventsManagerInterface) {
            $eventsManager->fire("auth:afterLogIn", $this);
        }

        return true;
    }

    public function logOut() : bool
    {
        $eventsManager = $this->getEventsManager();

        if ($eventsManager instanceof EventsManagerInterface) {
            if ($eventsManager->fire("auth:beforeLogOut", $this) === false) {
                return false;
            }
        }

        if (!$this->isLoggedIn()) {
            return true;
        }

        $di = $this->getDI();

        $session = $di->getShared("session");

        $session->remove("auth_userID");

        if ($eventsManager instanceof EventsManagerInterface) {
            $eventsManager->fire("auth:afterLogOut", $this);
        }

        return true;
    }



    /**
     * @return ModelInterface|boolean
     */
    public function getUser()
    {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $di = $this->getDI();

        $session = $di->getShared("session");

        $userID = $session->get("auth_userID");

        return $this->getUserFromUserId($userID);
    }

    /**
     * @return int|boolean
     */
    public function getUserID()
    {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $di = $this->getDI();

        $session = $di->getShared("session");

        return $session->get("auth_userID");
    }

    public function isLoggedIn() : bool
    {
        $di = $this->getDI();

        $session = $di->getShared("session");

        return $session->has("auth_userID");
    }

    /**
     * @return ModelInterface|boolean
     */
    public function getUserFromCredentials(string $username, string $password)
    {
        $user = call_user_func(
            [$this->modelName, "findFirst"],
            [
                $this->usernameField . " = :username:",
                "bind" => [
                    "username" => $username,
                ],
            ]
        );

        if (!$user) {
            return false;
        }

        $hashedPassword = $user->readAttribute($this->passwordField);

        $di = $this->getDI();

        $security = $di->getShared("security");

        if (!$security->checkHash($password, $hashedPassword)) {
            return false;
        }

        return $user;
    }

    public function getUserFromUserId(int $userID) : ModelInterface
    {
        $user = call_user_func(
            [$this->modelName, "findFirst"],
            [
                $this->userIdField . " = :userID:",
                "bind" => [
                    "userID" => $userID,
                ],
            ]
        );

        return $user;
    }

    public function getUserIdFromUser(ModelInterface $user) : int
    {
        return $user->readAttribute($this->userIdField);
    }



    public function changePassword(ModelInterface $user, string $newPassword) : bool
    {
        $eventsManager = $this->getEventsManager();

        if ($eventsManager instanceof EventsManagerInterface) {
            if ($eventsManager->fire("auth:beforeChangePassword", $this) === false) {
                return false;
            }
        }

        $di = $this->getDI();

        $security = $di->getShared("security");

        $user->writeAttribute(
            $this->passwordField,
            $security->hash($newPassword)
        );

        $success = $user->update();

        if ($eventsManager instanceof EventsManagerInterface) {
            $eventsManager->fire("auth:afterChangePassword", $this);
        }

        return $success;
    }



    public function createUser(string $username, string $password) : ModelInterface
    {
        $user = new $this->modelName();

        $di = $this->getDI();

        $security = $di->getShared("security");

        $user->writeAttribute($this->usernameField, $username);

        $user->writeAttribute(
            $this->passwordField,
            $security->hash($password)
        );

        return $user;
    }
}
