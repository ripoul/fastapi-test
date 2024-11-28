from pydantic import EmailStr
from sqlalchemy import String
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    first_name: str = Field(nullable=False)
    last_name: str = Field(nullable=False)
    email: EmailStr = Field(
        sa_type=String(),  # type: ignore[call-overload]
        unique=True,
        index=True,
        nullable=False,
        description="The email of the user",
    )


class UserPublic(UserBase):
    id: int | None = Field(default=None, primary_key=True)


class User(UserPublic, table=True):
    password: str = Field(nullable=False)


class UserCreate(UserBase):
    password: str = Field(nullable=False)
