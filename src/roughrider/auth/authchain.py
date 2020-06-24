import wrapt
from typing import Mapping
from roughrider.auth.meta import Authenticator
from horseman.response import Response


unauthorized = Response.create(401)


def resolve_auth(checkers: Mapping[str, Authenticator], environ):
    auth = environ.get('HTTP_AUTHORIZATION')
    if auth is not None:
        authtype, _ = auth.split(' ', 1)
        if (checker := checkers.get(authtype.lower())) is not None:
            if (user := checker.identify(environ)):
                environ['auth_payload'] = user
                return None
            return checker.unauthorized
    return unauthorized


def middleware(checkers, unauthorized=unauthorized):

    @wrapt.decorator
    def authenticator(wrapped, instance, args, kwargs):
        environ = args[0]
        if (response := resolve_auth(checkers, environ)) is not None:
            return response(*args)
        return wrapped(*args)

    return authenticator
