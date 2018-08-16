#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("db")
from datetime import datetime, timedelta
import sqlalchemy
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.declarative import declarative_base

def get_user(session, user_id):
    return session.query(User).filter(User.id==user_id).one_or_none()

def count_users(session):
    return session.query(func.count(User.id)).scalar()

def get_user_by_telegram_id(session, telegram_id):
    try:
        return session.query(User).filter(User.telegram_id==telegram_id).one()
    except:
        logger.info("Attempted to fetch user with telegram ID {} not found".format(telegram_id))
        return None

def get_balance(session, user=None, user_id=None):
    if not user_id:
        user_id = user.id
    return session.query(func.sum(Transaction.value)).filter(Transaction.user_id==user_id).scalar() or 0

def add_transaction(session, user, value, payment_request):
    trans = Transaction(user_id=user.id, value=value, payment_request=payment_request)
    session.add(trans)
    return trans

def count_transactions(session):
    return session.query(func.count(Transaction.id)).scalar()

def add_invoice(session, user, payreq_string):
    invoice = Invoice(user_id=user.id, payment_request=payreq_string)
    session.add(invoice)
    return invoice

def get_invoice(session, payreq_string):
    for invoice in session.query(Invoice).filter(Invoice.payment_request==payreq_string).all():
        return invoice.user

def set_invoice_context(session, user, payment_request, timeout_seconds):
    user.invoice_context = payment_request
    user.invoice_context_expiry = datetime.utcnow() + timedelta(seconds=timeout_seconds)

def get_invoice_context(session, user):
    if user.invoice_context and datetime.utcnow() < user.invoice_context_expiry:
        return user.invoice_context
    return None

def clear_invoice_context(session, user):
    user.invoice_context = None
    user.invoice_context_expiry = None

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    telegram_id = Column(Integer, unique=True)

    invoice_context = Column(String)
    invoice_context_expiry = Column(DateTime)

    transactions = relationship("Transaction", back_populates="user")
    invoices = relationship("Invoice", back_populates="user")
    
    def __repr__(self):
        return "<User {}>".format(self.id)

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    value = Column(Integer)
    payment_request = Column(String)

    user = relationship("User", back_populates="transactions")

    def __repr__(self):
        return "<Transaction {} {}>".format(self.user_id, self.value)

class Invoice(Base):
    __tablename__ = 'invoices'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    payment_request = Column(String, unique=True)

    user = relationship("User", back_populates="invoices")

    def __repr__(self):
        return "<Invoice {}...>".format(self.payment_request[:32])

def open_database(path):
    from sqlalchemy import create_engine
    engine = create_engine('sqlite:///' + path, echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)

