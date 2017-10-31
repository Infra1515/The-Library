"""empty message

Revision ID: 90895e397dbc
Revises: 42a8534cf10c
Create Date: 2017-10-31 17:32:52.682196

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '90895e397dbc'
down_revision = '42a8534cf10c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('postlikes',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('post_id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'post_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('postlikes')
    # ### end Alembic commands ###