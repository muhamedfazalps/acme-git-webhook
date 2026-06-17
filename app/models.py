from pydantic import BaseModel


class AcmeRequest(BaseModel):
    domain: str
    validation: str | None = None
