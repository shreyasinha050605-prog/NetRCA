from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./netrca.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

SCHEMA_UPDATES = {
    "log_events": [
        ("raw_message_hash", "TEXT"),
        ("target", "VARCHAR"),
        ("service", "VARCHAR"),
        ("port", "INTEGER"),
        ("context_json", "TEXT"),
        ("hmac_signature", "TEXT"),
        ("source_verified", "BOOLEAN DEFAULT 0"),
    ],
    "incidents": [
        ("updated_at", "DATETIME"),
        ("status", "VARCHAR DEFAULT 'open'"),
        ("severity_score", "FLOAT DEFAULT 0"),
        ("service", "VARCHAR"),
        ("port", "INTEGER"),
        ("causal_chain_json", "TEXT"),
        ("graph_json", "TEXT"),
        ("root_cause_nodes_json", "TEXT"),
        ("impact_nodes_json", "TEXT"),
        ("failure_nodes_json", "TEXT"),
        ("path_traces_json", "TEXT"),
        ("timeline_json", "TEXT"),
        ("ai_report_json", "TEXT"),
        ("last_analyzed_at", "DATETIME"),
    ],
}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)

    with engine.begin() as connection:
        for table_name, columns in SCHEMA_UPDATES.items():
            inspector = inspect(connection)
            existing_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            for column_name, column_definition in columns:
                if column_name not in existing_columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {column_name} {column_definition}"
                        )
                    )
        connection.execute(
            text(
                "UPDATE incidents "
                "SET updated_at = COALESCE(updated_at, detected_at), "
                "status = COALESCE(status, 'open'), "
                "severity_score = COALESCE(severity_score, 0)"
            )
        )
        connection.execute(
            text(
                "UPDATE log_events "
                "SET source_verified = COALESCE(source_verified, 0)"
            )
        )
