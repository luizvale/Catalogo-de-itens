# -*- coding: utf-8 -*-

import sys
from sqlalchemy import Integer, ForeignKey, String, Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

## sys fornece um conjunto de funções para lidar com dados em tempo de execução 
## sqlalchemy fornece/converte tratamento para banco de dados e tables em/para forma de objetos python

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)

    name = Column(String(250), nullable=False)

    email = Column(String(250), nullable=False)
    
    picture = Column(String(250))

    @property
    def serialize(self):
        return {
            'name': self.name,
            'e-mail': self.email,
            'client_key': self.id }
            
class Category(Base):
    __tablename__ = 'category_items'

    name = Column(String(80), nullable = False)
    
    id = Column(Integer, primary_key = True)

    description = Column(String(80), nullable = False)

    user_id = Column(Integer, ForeignKey('user.id'))

    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id, }


class Item(Base):
    __tablename__ = 'type_items'
    
    name = Column(String(80), nullable = False)
    
    id = Column(Integer, primary_key = True)
    
    course = Column(String(250))

    description = Column(String(250))

    price = Column(String(8))

    category_id = Column(Integer, ForeignKey('category_items.id'))

    type_items = relationship(Category)

    user_id = Column(Integer, ForeignKey('user.id'))

    user = relationship(User)

    @property   #json method
    def serialize(self):

        return {
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'id': self.id,
            'especify': self.especify }



engine = create_engine('sqlite:///accessories_store.db')
Base.metadata.create_all(engine)