## Generate new migration

alembic -c src/alembic.ini revision --autogenerate -m "un message"

## Apply migration

alembic -c src/alembic.ini upgrade head
