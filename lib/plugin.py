from typing import List, Optional

from safeguard.sessions.plugin import AAPlugin, AAResponse
from safeguard.sessions.plugin.plugin_base import cookie_property

from lib.authenticator import Authenticator
from lib.exceptions import FactorNotFound


class Plugin(AAPlugin):
    FACTOR_SELECTION_SUPPORTED_PROTOCOLS = ["ssh", "telnet"]

    def __init__(self, configuration):
        super().__init__(configuration)

        self.logger.info("Initializing plugin")

        client_id = self.plugin_configuration.get("onelogin", "client_id", required=True)
        client_secret = self.plugin_configuration.get("onelogin", "client_secret", required=True)
        region = self.plugin_configuration.get("onelogin", "api_region", default="us")
        user_attribute = self.plugin_configuration.get("onelogin", "user_attribute", default="username")

        self._authenticator = Authenticator(client_id, client_secret, region=region, user_attribute=user_attribute)

        self._factor_selection_enabled = self.plugin_configuration.getboolean("onelogin", "enable_factor_selection", default=True)
        self._enable_stacktrace = self.plugin_configuration.getboolean("logging", "enable_stacktrace", default=False)

        self.logger.debug("Plugin initialized")

    @cookie_property
    def _factor_selection_in_progress(self) -> bool:
        return False

    @cookie_property
    def _enrolled_factors(self) -> List[tuple]:
        return list()

    @cookie_property
    def _user_selected_factor_id(self) -> Optional[int]:
        return None

    @property
    def _factor_selection_supported(self) -> bool:
        return self.connection.protocol in self.FACTOR_SELECTION_SUPPORTED_PROTOCOLS

    @property
    def _factor_selection_prompt(self) -> str:
        prompt = ""
        for position, factor in enumerate(self._enrolled_factors, start=1):
            factor_display_name = factor[1]
            prompt += f"{position}) {factor_display_name}\n"
        prompt += "Select a factor: "
        return prompt

    def _init_factor_selection(self) -> AAResponse:
        self.logger.debug("Initializing factor selection")
        enrolled_factors = self._authenticator.get_enrolled_factors(self.mfa_identity)
        if not enrolled_factors:
            self.logger.info("No factors are available to select from")
            return AAResponse.deny(deny_reason="No factors found")
        self._enrolled_factors = [(f.id, f.user_display_name) for f in enrolled_factors]
        self._factor_selection_in_progress = True
        self.logger.debug(f"Factor selection initialized with factors={self._enrolled_factors}")
        return AAResponse.need_info(self._factor_selection_prompt, "user_factor_selection")

    def _finish_factor_selection(self) -> AAResponse:
        self.logger.info("Finishing factor selection")
        self._factor_selection_in_progress = False
        try:
            selection = self.connection.key_value_pairs.get("user_factor_selection", None)
            self.logger.debug(f"User selection received={selection or str('none')}")
            index = int(selection)-1
            if index < 0:
                raise ValueError
            self._user_selected_factor_id = self._enrolled_factors[index][0]
        except (ValueError, TypeError, IndexError):
            return AAResponse.deny(deny_reason="Invalid selection")
        self.connection.key_value_pairs.pop("otp")
        self.logger.debug(f"Successfully selected factor={self._user_selected_factor_id}")
        return self._ask_mfa_password()

    def _run_factor_selection_command(self):
        self.logger.info("Running factor selection")
        if not self._factor_selection_enabled:
            self.logger.info("Factor selection requested but it's not enabled")
            return AAResponse.deny(deny_reason="Factor selection not available")
        if not self._factor_selection_supported:
            self.logger.info(f"Factor selection not supported for protocol: {self.connection.protocol}")
            return AAResponse.deny(deny_reason="Factor selection not supported")
        return self._init_factor_selection()

    def do_authenticate(self):
        try:
            if self._factor_selection_in_progress:
                return self._finish_factor_selection()
            if self.mfa_password:
                if self.mfa_password == "!select":
                    return self._run_factor_selection_command()
                if self._authenticator.otp_authenticate(self.mfa_identity, self.mfa_password, factor_id=self._user_selected_factor_id):
                    self.logger.info("OTP authentication successful")
                    return AAResponse.accept(reason="OTP authentication successful")
                else:
                    self.logger.info("OTP authentication failed")
                    return AAResponse.deny(deny_reason="OTP authentication failed")
            else:
                self.logger.info(f"Running push authentication for user={self.mfa_identity} with factor={self._user_selected_factor_id or str('default')}")
                if self._authenticator.push_authenticate(self.mfa_identity, factor_id=self._user_selected_factor_id):
                    self.logger.info("Push verification accepted by user")
                    return AAResponse.accept(reason="Push verification successful")
                else:
                    self.logger.info("Push verification rejected by user")
                    return AAResponse.deny(deny_reason="Push verification failed")
        except Exception as e:
            self.logger.error(e, exc_info=self._enable_stacktrace)
        return AAResponse.deny(deny_reason="An error occured")