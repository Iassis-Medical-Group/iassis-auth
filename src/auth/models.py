from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standard error envelope (matches FastAPI's default HTTPException shape)."""

    detail: str = Field(..., examples=["Not authenticated"])
