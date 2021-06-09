import base64
from typing import Sequence, Optional, Dict
from roughrider.meta import Authenticator, User
from horseman.response import Response
from horseman.prototyping import Environ, WSGICallable


class BasicAuthMeta(Authenticator):

    realm: str
    forbidden: WSGICallable = Response.create(403)

    def credentials(self, environ: Environ) -> Optional[Sequence[str, str]]:
        """Extracts the basic auth credentials from the environ.
        """
        auth = environ.get('HTTP_AUTHORIZATION')
        if auth is not None:
            authtype, authvalue = auth.split(' ', 1)
            auth = base64.b64decode(authvalue)
            if isinstance(auth, bytes):
                auth = auth.decode()
                return auth.split(':', 1)
        return None

    @property
    def unauthorized(self):
        return Response.create(401, headers={
            'WWW-Authenticate':
            f'Basic realm="{self.realm}", charset="UTF-8"'
        })

    def remember(self, environ: Environ, user: User):
        """No-op for basic auth.
        """

    def forget(self, environ: Environ):
        """No-op for basic auth.
        """


class BasicAuth(BasicAuthMeta):

    def __init__(self, realm: str, users: Dict[str, str]):
        self.realm = realm
        self.users = users

    def identify(self, environ: Environ) -> User:
        """Returns the current active user.
        """
        credentials = self.credentials(environ)
        if credentials is None:
            return None
        username, password = credentials
        if username in self.users and self.users[username] == password:
            return username
        return None
