"""empty message

Revision ID: 42a8534cf10c
Revises: 94d6672766b1
Create Date: 2017-10-30 18:52:27.147131

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '42a8534cf10c'
down_revision = '94d6672766b1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('posts', sa.Column('body_html', sa.Text(), nullable=True))
    op.add_column('posts', sa.Column('title', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('posts', 'title')
    op.drop_column('posts', 'body_html')
    # ### end Alembic commands ###