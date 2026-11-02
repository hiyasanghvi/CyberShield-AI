from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class QRAnalysis(Base):
    __tablename__ = "qr_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    payload: Mapped[str | None] = mapped_column(EncryptedText())
    payload_type: Mapped[str | None] = mapped_column(String(50))
    decoded_url: Mapped[str | None] = mapped_column(EncryptedText())
    image_path: Mapped[str | None] = mapped_column(String(500))

    analysis = relationship("Analysis", backref="qr_analysis")
