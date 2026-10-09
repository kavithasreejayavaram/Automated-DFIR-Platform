from sqlalchemy.orm import Session
from app.db.database import engine, Base, SessionLocal
from app.db.models import User
from app.core.security import get_password_hash
from app.engine.detection import seed_detection_rules
from app.engine.threat_intel import seed_synthetic_iocs

def init_db(db: Session):
    Base.metadata.create_all(bind=engine)
    
    # Seed Admin User
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin_user = User(
            username="admin",
            email="admin@traceforensics.org",
            hashed_password=get_password_hash("admin123"),
            role="admin",
            is_active=True
        )
        db.add(admin_user)
    else:
        admin.email = "admin@traceforensics.org"

    # Seed Analyst User
    analyst = db.query(User).filter(User.username == "analyst").first()
    if not analyst:
        analyst_user = User(
            username="analyst",
            email="analyst@traceforensics.org",
            hashed_password=get_password_hash("analyst123"),
            role="analyst",
            is_active=True
        )
        db.add(analyst_user)
    else:
        analyst.email = "analyst@traceforensics.org"

    db.commit()

    # Seed rules & synthetic IOCs
    seed_detection_rules(db)
    seed_synthetic_iocs(db)

if __name__ == "__main__":
    db = SessionLocal()
    init_db(db)
    print("Database seeded successfully with demo users (admin/admin123, analyst/analyst123) and default detection rules.")
