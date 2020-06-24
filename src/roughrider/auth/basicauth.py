import base64
from typing import Sequence, Optional
from roughrider.meta import Authenticator, User
from horseman.response import Response
from horseman.prototyping import Environ


class BasicAuth(Authenticator):

    realm: str

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
        """No-op for the basic auth.
        """
