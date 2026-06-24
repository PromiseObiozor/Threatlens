from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[list["ScanHistory"]] = relationship(
        "ScanHistory",
        back_populates="owner",
        cascade="all, delete-orphan",
    )


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    sender: Mapped[str] = mapped_column(String)
    subject: Mapped[str] = mapped_column(String)
    reply_to: Mapped[str | None] = mapped_column(String, nullable=True)
    body_preview: Mapped[str] = mapped_column(Text)

    risk_score: Mapped[int] = mapped_column()
    label: Mapped[str] = mapped_column(String)

    ml_score: Mapped[int] = mapped_column()
    nlp_score: Mapped[int] = mapped_column()
    url_score: Mapped[int] = mapped_column()
    metadata_score: Mapped[int] = mapped_column()

    reasons: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped[User] = relationship("User", back_populates="scans")
