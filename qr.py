# -*- coding: utf-8 -*-
import zbar
from PIL import Image

def find_invoice(photo_file):
    scanner = zbar.ImageScanner()
    scanner.parse_config('enable')
    pil_image = Image.open(photo_file).convert('L')
    width, height = pil_image.size
    raw = pil_image.tobytes()
    zbar_image = zbar.Image(width, height, 'Y800', raw)
    result = scanner.scan(zbar_image)
    if result == 0:
        return
    for symbol in zbar_image:
        #print(symbol)
        pass
    data = symbol.data.decode('utf-8').lower()
    # TODO: Read up on lightnign QR invoice format
    if data.startswith("lightning:"):
        data = data[10:]
    return data
