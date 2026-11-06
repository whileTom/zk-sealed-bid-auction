"""Domain errors. Each carries a machine-readable code and the HTTP status the API returns."""


class DomainError(Exception):
    status = 400
    code = "BAD_REQUEST"

    def __init__(self, message: str, code: str = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class NotFound(DomainError):
    status = 404
    code = "NOT_FOUND"


class PhaseError(DomainError):
    """Action not allowed in the auction's current phase."""

    status = 409
    code = "WRONG_PHASE"


class Conflict(DomainError):
    status = 409
    code = "CONFLICT"


class InvalidInput(DomainError):
    status = 422
    code = "VALIDATION_ERROR"
