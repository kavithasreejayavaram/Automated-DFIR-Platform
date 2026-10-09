from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.schemas.schemas import BenchmarkResult
from app.scripts.evaluate import run_evaluation_benchmark
from app.db.models import User
from app.api.deps import get_current_user

router = APIRouter(prefix="/benchmark", tags=["Evaluation & Benchmarking"])

@router.post("/run", response_model=BenchmarkResult)
def trigger_benchmark_evaluation(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = run_evaluation_benchmark(db)
    return results
