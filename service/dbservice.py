import json
import os
import hashlib
from api.model.classes import *
import api.service.jwthelper as jwth
from types import SimpleNamespace
from datetime import date
from uuid import uuid4
from api.model.user import *
from api.model.items import *
from api.model.character import *
from api.model.spellbook import *
from api.service.config import config
from api.loghandler.logger import Logger
from api.model import db
from sqlalchemy.orm import sessionmaker, Query
from sqlalchemy import desc


class ClassService:
    query = Query(Class, db.session)
    querySubclass = Query(Subclass, db.session)

    @classmethod
    def getAll(cls):
        return cls.query.all()

    @classmethod
    def get(cls, id: str):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def getSubclass(cls, id: str):
        return cls.querySubclass.filter_by(id=id).first()

class AuthService:
    @classmethod
    def addDefaultRole(cls, user):
        roles = Query(UserRole, db.session).filter_by(userId=user.id).all()
        if roles is None or roles == []:
            user.roles.append(Query(Role, db.session).order_by(desc(Role.level)).first())
            db.session.commit()

    @classmethod
    def register_user(cls, user: User):
        nUser = User()
        nUser.salt = str(uuid4())
        nUser.password = cls._hash_password(user.password, nUser.salt)
        nUser.created = date.today()
        nUser.lastOnline = date.today()
        nUser.username = user.username
        nUser.email = user.email
        db.session.add(nUser)
        db.session.commit()
        cls.addDefaultRole(nUser)
        return nUser

    @classmethod
    def _hash_password(cls, password: str, salt: str) -> str:
        secret = config('security')
        try:
            sha = hashlib.sha256()
            sha.update(password.encode(encoding = 'UTF-8', errors = 'strict'))
            sha.update(':'.encode(encoding = 'UTF-8'))
            sha.update(salt.encode(encoding = 'UTF-8', errors = 'strict'))
            sha.update(secret['usersecret'].encode(encoding = 'UTF-8', errors = 'strict'))
            return sha.hexdigest()
        except Exception as error:
            Logger.error(error)
        return None

    @classmethod
    def authenticate_user(cls, user: User) -> User | None:
        query = Query(User, db.session)
        secret = user.password
        if user.username is not None:
            user = query.filter_by(username=str.lower(user.username)).first()
        elif user.email is not None:
            user = query.filter_by(email=user.email).first()
        else:
            Logger.error('Attempted to authenticate without email or username provided, or both were provided.')
            return None
        if not user:
            Logger.error('no user')
            return None
        else:
            if AuthService._hash_password(secret, user.salt) == user.password:
                user.lastOnline = date.today()
                db.session.commit()
                cls.addDefaultRole(user)
                return jwth.create_token(user)
            else:
                Logger.error('Incorrect password!')
                return None