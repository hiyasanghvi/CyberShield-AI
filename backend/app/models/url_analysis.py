from sqlalchemy import String, Boolean, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class URLAnalysis(Base):
    __tablename__ = "url_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    url: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    domain: Mapped[str | None] = mapped_column(EncryptedText())
    https_enabled: Mapped[bool | None] = mapped_column(Boolean)
    url_length: Mapped[int | None] = mapped_column(Integer)
    domain_length: Mapped[int | None] = mapped_column(Integer)
    num_subdomains: Mapped[int | None] = mapped_column(Integer)
    has_ip_address: Mapped[bool | None] = mapped_column(Boolean)
    has_suspicious_keyword: Mapped[bool | None] = mapped_column(Boolean)

    analysis = relationship("Analysis", backref="url_analysis")
