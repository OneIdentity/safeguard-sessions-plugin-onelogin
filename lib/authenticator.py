import time
from datetime import datetime, timedelta
from typing import List, Optional

from onelogin.api.models.user import User
from onelogin.api.models.otp_device import OTP_Device
from onelogin.api.models.factor_enrollment_response import FactorEnrollmentResponse
from onelogin.api.client import OneLoginClient

from .exceptions import FactorNotFound, OneLoginClientError, APIResponseError, UserNotFound, FactorNotFound, TimeOutError


class Authenticator:
    PUSH_VERIFICATION_POLL_FREQUENCY = 5  # seconds
    PUSH_VERIFICATION_POLL_TIMEOUT = 60   # seconds

    def __init__(self, client_id: str, client_secret: str, region: str = "us", user_attribute: str = "username"):
        self._client_id = client_id
        self._client_secret = client_secret
        self._region = region
        self._user_attribute = user_attribute

        self._client = OneLoginClient(self._client_id, self._client_secret, self._region)
        self._verify_client()

    def _verify_client(self) -> None:
        if self._client.get_access_token() is None:
            raise OneLoginClientError(self._client.error_description)

    def _get_user(self, username: str) -> User:
        query_params = {self._user_attribute: username, "fields": "id"}
        users = self._client.get_users(query_params)
        if users is None:
            raise APIResponseError(self._client.error_description)
        elif len(users) > 1:
            raise APIResponseError(f"More than one user found for user: {username} based on attribute: {self._user_attribute}")
        elif len(users) < 1:
            raise UserNotFound(f"No user found for user: {username} based on attribute: {self._user_attribute}")
        return users.pop()

    def _get_default_factor(self, username: str) -> OTP_Device:
        factors = self.get_enrolled_factors(username)
        default_factor = next((factor for factor in factors if factor.default), None)
        if default_factor is None:
            raise FactorNotFound("No default MFA factor found")
        return default_factor

    def _activate_factor(self, user_id: int, factor_id: int, expires_in: Optional[int] = None) -> FactorEnrollmentResponse:
        response = self._client.activate_factor(user_id, factor_id, expires_in=expires_in)
        if response is None:
            raise APIResponseError(self._client.error_description)
        return response

    def get_enrolled_factors(self, username: str) -> List[OTP_Device]:
        user = self._get_user(username)
        factors = self._client.get_enrolled_factors(user.id)
        if factors is None:
            raise APIResponseError(self._client.error_description)
        return factors

    def otp_authenticate(self, username: str, otp: str, factor_id: Optional[int] = None) -> bool:
        user = self._get_user(username)
        factor_id = factor_id or self._get_default_factor(username).id
        return self._client.verify_factor(user.id, factor_id, otp)

    def push_authenticate(self, username: str, factor_id: Optional[int] = None) -> bool:
        user = self._get_user(username)
        factor_id = factor_id or self._get_default_factor(username).id
        activation = self._activate_factor(user.id, factor_id, expires_in=self.PUSH_VERIFICATION_POLL_TIMEOUT)
        expires_at = datetime.now() + timedelta(seconds=self.PUSH_VERIFICATION_POLL_TIMEOUT)
        while expires_at > datetime.now():
            response = self._client.verify_factor_poll(user.id, activation.id)
            if response.status == "pending":
                time.sleep(self.PUSH_VERIFICATION_POLL_FREQUENCY)
                continue
            elif response.status == "accepted":
                return True
            elif response.status == "rejected":
                return False
            else:
                raise APIResponseError(f"Push verification status not recognized: {response.status}")
        raise TimeOutError("Push verification timed out")