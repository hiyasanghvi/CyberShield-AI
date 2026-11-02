from sqlalchemy import String, Text, Integer, BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.db.encrypted import EncryptedText


class APKAnalysis(Base):
    __tablename__ = "apk_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
        unique=True,
    )

    file_name: Mapped[str | None] = mapped_column(EncryptedText())
    file_hash: Mapped[str | None] = mapped_column(EncryptedText())
    package_name: Mapped[str | None] = mapped_column(String(255))
    version_name: Mapped[str | None] = mapped_column(String(100))
    version_code: Mapped[int | None] = mapped_column(Integer)
    permissions: Mapped[str | None] = mapped_column(EncryptedText())
    suspicious_apis: Mapped[str | None] = mapped_column(EncryptedText())
    extracted_urls: Mapped[str | None] = mapped_column(EncryptedText())
    file_size: Mapped[int | None] = mapped_column(BigInteger)

    analysis = relationship("Analysis", backref="apk_analysis")
