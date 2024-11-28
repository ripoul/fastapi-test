from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlmodel import select

from database import SessionDep
from models import User, UserCreate, UserPublic
from security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    Token,
    authenticate_user,
    create_access_token,
    encrypt_pass,
    get_current_user,
)

router = APIRouter(prefix="/users", tags=["users"])


class ErrorFormat(BaseModel):
    detail: str


@router.get("/", response_model=list[UserPublic])
async def read_users(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    return (await session.execute(select(User).offset(offset).limit(limit))).scalars().all()


@router.get(
    "/{user_id}",
    response_model=UserPublic,
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "User with requested id not found",
            "model": ErrorFormat,
        }
    },
)
async def read_item(
    item_id: int,
    session: SessionDep,
):
    user = await session.get(User, item_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/", response_model=UserPublic)
async def create_user(user: UserCreate, session: SessionDep):
    db_user = User.model_validate(user)
    db_user.password = encrypt_pass(db_user.password)
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)
    return db_user


@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep
) -> Token:
    user = await authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me/", response_model=UserPublic)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return current_user
