from datetime import datetime

from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    indicator_value: Mapped[str] = mapped_column(
        EncryptedText,
        nullable=False,
    )

    source: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    analysis = relationship(
        "Analysis",
        backref="threat_indicators",
    )
