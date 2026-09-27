#!/usr/bin/env python3
"""Which pre-boot or recovery screen a winvm screenshot shows (1280x800, VGA).

    winre.py SHOT.png   ->  repair | options | bitlocker | other

  repair     "Automatic Repair / Your PC did not start correctly"
             (buttons: Restart, Advanced options)
  options    "Choose an option" (tiles: Continue, Use a device, Troubleshoot,
             Turn off your PC)
  bitlocker  "BitLocker recovery" (the recovery key prompt: the TPM did not
             unseal)
  other      anything else

DESIGN.md §4.4: a VM that the tripwire stops while Windows boots leaves a
failed boot recorded on C:, so the next boot shows Automatic Repair once and
"Continue" boots normally. split-e2e.sh answers it the way the launcher's
message tells the user to: Advanced options, then Continue (the click targets
below). Pixels are sampled at fixed points of these fixed layouts, so an
unexpected screen reads as "other" and nothing gets clicked.
"""
import sys

from PIL import Image

SIZE = (1280, 800)
BLUE = (32, 103, 178)      # the recovery screens' background
WHITE = (255, 255, 255)    # Automatic Repair's button borders
TILE = (77, 167, 221)      # "Choose an option" tiles
KEYBOX = (205, 205, 205)   # BitLocker recovery's key entry box

ADVANCED_OPTIONS = (873, 294)
CONTINUE = (350, 190)


def near(a, b, tol=12):
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def classify(path):
    im = Image.open(path).convert("RGB")
    if im.size != SIZE:
        return "other"
    px = im.getpixel
    if not (near(px((600, 295)), BLUE) and near(px((700, 500)), BLUE)):
        return "other"
    if all(near(px(p), KEYBOX) for p in [(190, 165), (300, 172), (700, 172), (745, 180)]):
        return "bitlocker"
    if near(px((687, 295)), WHITE) and near(px((797, 295)), WHITE) and near(px((820, 300)), BLUE):
        return "repair"
    if all(near(px(p), TILE) for p in [(235, 215), (655, 215), (235, 495)]):
        return "options"
    return "other"


if __name__ == "__main__":
    print(classify(sys.argv[1]))
