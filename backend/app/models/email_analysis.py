from sqlalchemy import String, Boolean, Text, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedJSON, EncryptedText


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    sender_email: Mapped[str | None] = mapped_column(EncryptedText())
    subject: Mapped[str | None] = mapped_column(EncryptedText())
    body: Mapped[str | None] = mapped_column(EncryptedText())
    contains_url: Mapped[bool | None] = mapped_column(Boolean)
    url_count: Mapped[int | None] = mapped_column(Integer)
    has_attachment: Mapped[bool | None] = mapped_column(Boolean)
    header_data: Mapped[dict | None] = mapped_column(EncryptedJSON())

    analysis = relationship("Analysis", backref="email_analysis")
