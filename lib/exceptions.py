class PluginError(Exception):
    pass


class OneLoginClientError(PluginError):
    pass


class UserNotFound(PluginError):
    pass


class FactorNotFound(PluginError):
    pass


class TimeOutError(PluginError):
    pass


class APIResponseError(PluginError):
    pass