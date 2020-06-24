from abc import ABC, abstractmethod
from horseman.prototyping import Environ, WSGICallable


class User(ABC):
    username: str


class Authenticator(ABC):

    unauthorized: WSGICallable
    forbidden: WSGICallable

    @abstractmethod
    def identify(self, environ: Environ) -> User:
        """Returns the current active user.
        """

    @abstractmethod
    def remember(self, environ: Environ, user: User):
        """Saves the user for further identity checks.
        """

    @abstractmethod
    def forget(self, environ: Environ):
        """Resets the user, emptying the stroe identity information.
        """
