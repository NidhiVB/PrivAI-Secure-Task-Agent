"""API v1 master router."""

from fastapi import APIRouter
from backend.app.api.v1.agent import router as agent_router
from backend.app.api.v1.audit import router as audit_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.prompts import router as prompts_router
from backend.app.api.v1.reviews import router as reviews_router
from backend.app.employees.api import router as employees_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(prompts_router)
api_router.include_router(reviews_router)
api_router.include_router(audit_router)
api_router.include_router(agent_router)
api_router.include_router(employees_router)


