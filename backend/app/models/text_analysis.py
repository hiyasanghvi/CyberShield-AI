from sqlalchemy import String, Boolean, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class TextAnalysis(Base):
    __tablename__ = "text_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    text_content: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    language: Mapped[str | None] = mapped_column(String(50))
    contains_url: Mapped[bool | None] = mapped_column(Boolean)
    contains_phone: Mapped[bool | None] = mapped_column(Boolean)
    contains_money_indicator: Mapped[bool | None] = mapped_column(Boolean)
    contains_urgency: Mapped[bool | None] = mapped_column(Boolean)

    analysis = relationship("Analysis", backref="text_analysis")
