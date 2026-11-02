from datetime import datetime

from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class ThreatRelationship(Base):
    __tablename__ = "threat_relationships"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    source_indicator_id: Mapped[int] = mapped_column(
        ForeignKey("threat_indicators.id"),
        nullable=False,
    )

    target_indicator_id: Mapped[int] = mapped_column(
        ForeignKey("threat_indicators.id"),
        nullable=False,
    )

    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    source_indicator = relationship(
        "ThreatIndicator",
        foreign_keys=[source_indicator_id],
    )

    target_indicator = relationship(
        "ThreatIndicator",
        foreign_keys=[target_indicator_id],
    )