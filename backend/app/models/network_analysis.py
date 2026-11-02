from sqlalchemy import String, Integer, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class NetworkAnalysis(Base):
    __tablename__ = "network_analyses"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        EncryptedText()
    )

    destination_ip: Mapped[str | None] = mapped_column(
        EncryptedText()
    )

    protocol: Mapped[str | None] = mapped_column(
        String(20)
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer
    )

    duration: Mapped[float | None] = mapped_column(
        Float
    )

    total_bytes: Mapped[int | None] = mapped_column(
        Integer
    )

    total_packets: Mapped[int | None] = mapped_column(
        Integer
    )

    flow_rate: Mapped[float | None] = mapped_column(
        Float
    )

    attack_category: Mapped[str | None] = mapped_column(
        String(100)
    )

    analysis = relationship(
        "Analysis",
        backref="network_analysis",
    )
