
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from app.core.security import get_current_user
from app.models.user import User
from app.services.safety_assistant_service import get_safety_advice
from app.services.emergency_guide_service import get_emergency_guide

router = APIRouter(
    prefix="/api/safety",
    tags=["Cyber Safety Assistant"],
)


class SafetyQuestion(BaseModel):
    message: str = Field(min_length=3, max_length=5000)
    language: str = "hinglish"


@router.post("/assistant")
def ask_safety_assistant(
    request: SafetyQuestion,
    current_user: User = Depends(get_current_user),
):
    try:
        return get_safety_advice(
            message=request.message,
            language=request.language,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@router.get("/emergency-guide/{incident_type}")
def emergency_guide(
    incident_type: str,
    current_user: User = Depends(get_current_user),
):
    return get_emergency_guide(incident_type)
