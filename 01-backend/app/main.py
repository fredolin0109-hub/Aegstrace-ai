from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db
from app.routes import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    init_db()
    yield
    # Shutdown logic (if any)


app = FastAPI(
    title="AEGISTRACE Cybersecurity Platform API",
    description="Backend services for AI-powered phishing detection, agentic investigation, and UiPath RPA automated security response.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS for Frontend Dashboard and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=r"^chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes with /api prefix
app.include_router(api_router, prefix=settings.API_PREFIX)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global catch-all exception handler providing consistent structured error responses."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": str(exc) if settings.DEBUG else "An unexpected error occurred during security processing.",
            "path": request.url.path,
        },
    )


@app.get("/", tags=["Root"])
def root():
    return {
        "service": "AEGISTRACE Cybersecurity Platform",
        "status": "online",
        "api_docs": "/docs",
        "health_check": f"{settings.API_PREFIX}/health",
        "demo_mode": settings.DEMO_MODE,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )
