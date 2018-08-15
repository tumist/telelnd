# -*- coding: utf-8 -*-
from decimal import Decimal

def balance(amount):
    msg = "⚖️ Your balance is *{}* satoshis".format(amount)
    btc_rounded = (amount / Decimal(100000000)).quantize(Decimal('0.0001'))
    if btc_rounded > 0:
        msg += ", or about *{}* bitcoins".format(btc_rounded)
    return msg

def invoice(payment_request, ln_invoice, with_payment_request=True):
    invoice_text = u"⚡️Lightning invoice"
    invoice_text += u" for *{}* satoshis".format(ln_invoice.num_satoshis)
    try:
        memo = ln_invoice.description
    except:
        memo = None
    if memo:
        invoice_text += u": _{}_".format(memo)
    if not with_payment_request:
        return invoice_text
    payment_request_pre = "`{}`".format(payment_request)
    return u'\n\n'.join([invoice_text, payment_request_pre])

def expired_invoice(*args, **kwargs):
    msg = invoice(*args, **kwargs)
    msg += u'\n\n' + "⌛️ This invoice is now expired. "
    return msg

def settled_invoice(*args, **kwargs):
    msg = invoice(*args, **kwargs)
    msg += u'\n\n' + u"✅ This invoice has been paid"
    return msg

def payment_sent(sent, fees):
    msg = "💸 Paid *{}* satoshis with *{}* satoshis in fees ".format(sent, fees)
    return msg

def exception(e):
    msg = u"An error occured communicating with lnd"
    if hasattr(e, 'details'):
        msg += u": \n`{}`".format(e.details())
    return msg

def help():
    return """Here are the commands that I understand

/balance - Shows your account balance
/invoice amount [memo] - Creates a lightning invoice
/pay [invoice] - Pay an invoice

It is also possible to send me an invoice as text
or a QR photo and then pay it later using /pay."""
