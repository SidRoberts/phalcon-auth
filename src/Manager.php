<?php

namespace Sid\Phalcon\Auth;

use Phalcon\DiInterface;
use Phalcon\Di\Injectable;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Events\ManagerInterface as EventsManagerInterface;
use Phalcon\Mvc\ModelInterface;

class Manager extends Injectable implements EventsAwareInterface
{
    /**
     * @var EventsManagerInterface
     */
    protected $_eventsManager;

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
     * @param string $modelName
     * @param string $usernameField
     * @param string $passwordField
     * @param string $userIdField
     *
     * @throws Exception
     */
    public function __construct($modelName, $usernameField, $passwordField, $userIdField)
    {
        $di = $this->getDI();
        if (!($di instanceof DiInterface)) {
            throw new Exception("A dependency injection object is required to access internal services");
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
        return $this->_eventsManager;
    }

    /**
     * @param EventsManagerInterface $eventsManager
     */
    public function setEventsManager(EventsManagerInterface $eventsManager)
    {
        $this->_eventsManager = $eventsManager;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return boolean
     */
    public function logIn($username, $password)
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

        $this->getDI()->getShared("session")->set(
            "auth_userID",
            $userID
        );

        if ($eventsManager instanceof EventsManagerInterface) {
            $eventsManager->fire("auth:afterLogIn", $this);
        }

        return true;
    }

    /**
     * @return boolean
     */
    public function logOut()
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

        $this->getDI()->getShared("session")->remove("auth_userID");

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

        $userID = $this->getDI()->getShared("session")->get("auth_userID");

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

        return $this->getDI()->getShared("session")->get("auth_userID");
    }

    /**
     * @return boolean
     */
    public function isLoggedIn()
    {
        return $this->getDI()->getShared("session")->has("auth_userID");
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return ModelInterface|boolean
     */
    public function getUserFromCredentials($username, $password)
    {
        $user = call_user_func(
            [$this->modelName, "findFirst"],
            [
                $this->usernameField . " = :username:",
                "bind" => [
                    "username" => $username
                ]
            ]
        );

        if (!$user) {
            return false;
        }

        if (!$this->getDI()->getShared("security")->checkHash($password, $user->readAttribute($this->passwordField))) {
            return false;
        }

        return $user;
    }

    /**
     * @param int $userID
     *
     * @return ModelInterface
     */
    public function getUserFromUserId($userID)
    {
        $user = call_user_func(
            [$this->modelName, "findFirst"],
            [
                $this->userIdField . " = :userID:",
                "bind" => [
                    "userID" => $userID
                ]
            ]
        );

        return $user;
    }

    /**
     * @param ModelInterface $user
     *
     * @return int
     */
    public function getUserIdFromUser(ModelInterface $user)
    {
        return $user->readAttribute($this->userIdField);
    }

    /**
     * @param ModelInterface $user
     * @param string                      $newPassword
     *
     * @return boolean
     */
    public function changePassword(ModelInterface $user, $newPassword)
    {
        $eventsManager = $this->getEventsManager();

        if ($eventsManager instanceof EventsManagerInterface) {
            if ($eventsManager->fire("auth:beforeChangePassword", $this) === false) {
                return false;
            }
        }

        $user->writeAttribute(
            $this->passwordField,
            $this->getDI()->getShared("security")->hash($newPassword)
        );

        $success = $user->update();

        if ($eventsManager instanceof EventsManagerInterface) {
            $eventsManager->fire("auth:afterChangePassword", $this);
        }

        return $success;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return ModelInterface
     */
    public function createUser($username, $password)
    {
        $user = new $this->modelName();

        $user->writeAttribute($this->usernameField, $username);

        $user->writeAttribute(
            $this->passwordField,
            $this->getDI()->getShared("security")->hash($password)
        );

        return $user;
    }
}
