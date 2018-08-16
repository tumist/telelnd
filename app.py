#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
#
# It's a good idea to take a look at the globals defined below
# these imports before running.
#
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")
# telegram imports
import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
# lndrpc imports
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc
# python imports
import sys
import os
os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
import io
import re
from functools import wraps
import qrcode
# local imports
import qr
import db
import messages

# Configuration globals
# Most have somewhat sane defaults
#
# Create a bot token: https://core.telegram.org/bots#creating-a-new-bot
BOT_TOKEN = os.environ.get("BOT_TOKEN")
# Won't start on mainnet unles you switch this to False
TESTNET = True
# Invoice settle window in seconds. lnd default is 3600s
INVOICE_EXPIRE = 3600
# Path to lnd's TLS certificate
CERT_PATH = os.path.expanduser("~/.lnd/tls.cert")
# lnd gRPC interface
LND_GRPC = os.environ.get("LND", "localhost:10009")
# Timeout in seconds
GRPC_TIMEOUT = 60
# SQLite3 database path
DB_PATH = os.environ.get("DATABASE", "telelnd.db")

# There are a few global singletons used throughout the script
# which are initialized in main().
# They are defined here for readability
#
# RPC connection to lnd
stub = None # :: lnrpc.LightningStub
# SqlAlchemy session (database transaction) maker
sessionmaker = None # :: () -> SqlAlchemy Session
# Telegram bot
updater = None # :: Telegram Updater

# Utility functions

def decode_invoice(string):
    """Decode invoice using lnd"""
    # First do a quick negative test on the human-readable part
    # NOTE: lnd does not currently support invoices without
    # amount so we don't either
    if not re.match("^ln(bc|tb)[0-9]+[munp]", string):
        return
    return stub.DecodePayReq(
        ln.PayReqString(pay_req=string),
        timeout=GRPC_TIMEOUT)

# Command wrappers

def with_session(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        session = sessionmaker()
        try:
            return func(session, *args, **kwargs)
        except:
            session.rollback()
            raise
        finally:
            session.close()
    return wrapped

def with_user(func):
    """Restricts access to Handler to Users in our database"""
    @wraps(func)
    def wrapped(session, bot, update, *args, **kwargs):
        euid = update.effective_user
        if euid is None:
            return
        if euid.is_bot:
            return
        logger.debug("Effective user id: {}".format(euid.id))
        user = db.get_user_by_telegram_id(session, euid.id)
        if user:
            return func(user, session, bot, update, *args, **kwargs)
    return wrapped

# Command handlers

@with_session
def command_start(session, bot, update):
    # don't serve bots
    if update.effective_user.is_bot:
        return
    if not update.effective_user:
        return
    user = db.get_user_by_telegram_id(session, update.effective_user.id)
    if user:
        update.message.reply_text("Hi @{}".format(update.message.from_user.username))

@with_session
@with_user
def command_balance(user, session, bot, update):
    """
    /balance
    Show's the users balance
    """
    balance = db.get_balance(session, user)
    logger.info("{} has balance {}".format(user, balance))
    update.message.reply_markdown(messages.balance(balance))

@with_session
@with_user
def command_invoice(user, session, bot, update, args=[]):
    """
    /invoice amount [memo]
    Create an invoice in lnd and present user with payment
    request string and a QR code version
    """
    try:
        amount = int(args[0])
    except IndexError:
        update.message.reply_text("You need to specify an amount of satoshis")
        return
    except ValueError:
        update.message.reply_text("Invalid amount of satoshis")
        return
    if amount > 4294967:
        update.message.reply_text("The requested amount is too large for the lightning network")
        return
    if amount < 1:
        update.message.reply_text("Amount must be positive")
        return
    memo = u' '.join(args[1:])
    try:
        added = stub.AddInvoice(
            ln.Invoice(value=amount, memo=memo, expiry=INVOICE_EXPIRE),
            timeout=GRPC_TIMEOUT)
    except Exception, e:
        update.message.reply_markdown(messages.exception(e))
        raise e
    logger.debug(added)
    payment_request = added.payment_request
    invoice = decode_invoice(payment_request)
    logger.debug(invoice)
    logger.info("Created invoice for user {}: {}".format(user, payment_request))
    db.add_invoice(session, user, payment_request)
    session.commit()
    reply = update.message.reply_markdown(messages.invoice(payment_request, invoice))

    # Also create a scannable QR code
    photofile = io.BytesIO()
    qrcode.make(payment_request).save(photofile, format='png')
    photofile.seek(0)
    sent_photo = bot.send_photo(chat_id=update.message.chat_id, photo=photofile,
                                parse_mode=telegram.ParseMode.MARKDOWN)

def pay(user, session, bot, update, payment_request):
    try:
        decode_payreq = decode_invoice(payment_request)
        if not decode_payreq:
            update.message.reply_text("This doesn't look like an invoice")
            return
    except Exception, e:
        update.message.reply_markdown(messages.exception(e))
        raise e
    logger.debug(decode_payreq)
    satoshis = decode_payreq.num_satoshis
    destination = decode_payreq.destination

    if satoshis > db.get_balance(session, user):
        update.message.reply_text("Insufficient funds")
        return

    logger.info("{} initiating payment of {}".format(user, payment_request))
    update.message.reply_text("Sending payment...")

    # XXX: This is a synchonous command, will block until GRPC_TIMEOUT
    try:
        ret = stub.SendPaymentSync(
            ln.SendRequest(payment_request=payment_request),
            timeout=GRPC_TIMEOUT)
    except Exception, e:
        update.message.reply_markdown(messages.exception(e))
        raise e

    if ret.payment_route \
        and ret.payment_route.total_amt > 0:
        # Payment successfully went through
        sent_amount = ret.payment_route.total_amt
        num_hops = len(ret.payment_route.hops)
        fee_amount = sent_amount - satoshis
        logger.info("{} sent payment of {} satoshis to {}".format(user, sent_amount, destination))
        db.add_transaction(session, user, -sent_amount, payment_request)
        session.commit()
        update.message.reply_markdown(messages.payment_sent(sent_amount, fee_amount))
    else:
        if ret.payment_error:
            update.message.reply_text("Could not send payment: `{}`".format(ret.payment_error),
                                      parse_mode=telegram.ParseMode.MARKDOWN)
            logger.info("Error paying {}: {}".format(payment_request, ret.payment_error))
        else:
            update.message.reply_text("Could not send payment")
            logger.info("Error paying {}".format(payment_request))

@with_session
@with_user
def command_pay(user, session, bot, update, args=[]):
    """
    /pay [payment request]
    If args is set, we expect it to be a payment request string.
    Else, we see if we have a recent payment request in context to pay.
    """
    if args:
        return pay(user, session, bot, update, args[0])
    else:
        ctx = db.get_invoice_context(session, user)
        if ctx:
            db.clear_invoice_context(session, user)
            session.commit()
            return pay(user, session, bot, update, ctx)
    update.message.reply_text("Pay what?")

@with_session
@with_user
def photo_handler(user, session, bot, update):
    logger.debug("Received photo from {}".format(user))
    for photo_size in update.message.photo:
        logger.debug("{file_id} - {width}x{height} - {file_size}".format(**vars(photo_size)))
    # Just going for the last file here because in my tests
    # that last one was the largest
    largest_photo = bot.get_file(update.message.photo[-1])
    photo_bytes = io.BytesIO()
    largest_photo.download(out=photo_bytes)
    photo_bytes.seek(0)
    payment_request = qr.find_invoice(photo_bytes)
    if not payment_request:
        update.message.reply_text("Could not find a QR code in this image")
        logger.info("No recognized data in photo from {}".format(user))
        return
    try:
        invoice = decode_invoice(payment_request)
    except Exception, e:
        update.message.reply_markdown(messages.exception(e))
        raise e
    update.message.reply_text("I see your invoice")
    update.message.reply_markdown(messages.invoice(payment_request, invoice))
    db.set_invoice_context(session, user, payment_request, 60)
    session.commit()
    logger.info("{} sent photo with payment_request={}".format(user, payment_request))
    update.message.reply_text("Pay it using the /pay command")

@with_session
@with_user
def text_handler(user, session, bot, update):
    # Search user message for a lightning invoice
    # If found, store it and offer to pay it
    for token in update.message.text.split():
        try:
            invoice = decode_invoice(token)
        except:
            continue
        if invoice:
            invoice_owner = db.get_invoice(session, token)
            if invoice_owner and invoice_owner == user:
                update.message.reply_text("This is your own invoice")
                return
            db.set_invoice_context(session, user, token, 60)
            session.commit()
            update.message.reply_markdown(
                messages.invoice(token, invoice, with_payment_request=False))
            update.message.reply_markdown("Use the /pay command to pay this invoice")
            return

def help_handler(bot, update):
    update.message.reply_markdown(messages.help())

# Payments listener listens for incoming payments
# and handles accordingly.
# TODO: There ought to be a way to do a scan of settled payments
# to catch missed payments.
# TODO: This does not survive any hiccups.
def payments_listener_thread():
    logger.debug("payments_listener thread started")
    for invoice in stub.SubscribeInvoices(ln.InvoiceSubscription()):
        if hasattr(invoice, 'settled') and invoice.settled == True:
            handle_payment(invoice)
    logger.critical("paymens_listener thread ended")

@with_session
def handle_payment(session, invoice):
    logger.debug("Incoming payment\n{}".format(invoice))
    try:
        amount = int(invoice.value)
        amount_str = str(amount)
        if amount <= 0:
            raise
    except:
        amount = None
        amount_str = u"💯"
    memo = invoice.memo

    try:
        dbinv = session.query(db.Invoice).filter(db.Invoice.payment_request==invoice.payment_request).one()
    except: # sqlalchemy.orm.exc.NoResultFound
        logger.critical("Unable to find owner of settled invoice {}!".format(invoice.payment_request))
        return
    db.add_transaction(session, dbinv.user, amount, invoice.payment_request)
    logger.info("Settled invoice {} for user {}".format(dbinv, dbinv.user))
    session.commit()
    # Notify owner of invoice
    message = u"💵 Received *{}* satoshis for invoice _{}_".format(amount_str, memo)
    updater.bot.send_message(chat_id=dbinv.user.telegram_id,
                             text=message, parse_mode=telegram.ParseMode.MARKDOWN)

def main():
    if not BOT_TOKEN:
        sys.stderr.write("Please specify BOT_TOKEN environment variable\n")
        return 1

    # Open database
    global sessionmaker
    logger.info("Opening database {}".format(DB_PATH))
    sessionmaker = db.open_database(DB_PATH)
    session = sessionmaker()
    logger.info("Counting {} users and {} transactions".format(
        db.count_users(session), db.count_transactions(session)))
    session.close()

    # Connect to lightning gRPC
    global stub
    logger.info("Reading TLS certificate {}".format(CERT_PATH))
    cert = open(CERT_PATH, 'rb').read()
    creds = grpc.ssl_channel_credentials(cert)
    logger.info("Connecting to lnd at {}".format(LND_GRPC))
    channel = grpc.secure_channel(LND_GRPC, creds)
    stub = lnrpc.LightningStub(channel)
    # Do a test call
    info = stub.GetInfo(ln.GetInfoRequest(), timeout=GRPC_TIMEOUT)
    logger.info(info)
    logger.info("Connected to lnd".format(info.alias))
    if not info.testnet and TESTNET:
        logger.critical("lnd is running on mainnet, quitting")
        sys.exit(1)
    if not info.synced_to_chain:
        logger.critical("lnd is not synced")
        sys.exit(1)
    if not info.chains == ["bitcoin"]:
        logger.critical("Only bitcoin is supported at this time")
        sys.exit(1)

    # Create the telegram bot
    global updater
    updater = Updater(token=BOT_TOKEN)
    updater.dispatcher.add_handler(CommandHandler('start', command_start))
    updater.dispatcher.add_handler(CommandHandler('balance', command_balance))
    updater.dispatcher.add_handler(CommandHandler('invoice', command_invoice, pass_args=True))
    updater.dispatcher.add_handler(CommandHandler('pay', command_pay, pass_args=True))
    updater.dispatcher.add_handler(CommandHandler('help', help_handler))
    updater.dispatcher.add_handler(MessageHandler(Filters.photo, photo_handler))
    updater.dispatcher.add_handler(MessageHandler(Filters.text, text_handler))
    updater.start_polling()
    
    # Payments listener in a new thread
    import thread
    thread.start_new_thread(payments_listener_thread, ())
    
    logger.info("Bot started")
    
    # Wait until telegram poller stops or ^C
    updater.idle()
    return 0

if __name__ == "__main__":
    sys.exit(main())
