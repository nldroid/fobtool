#!/usr/bin/env python3
"""
fobtool.py - read and write a 7-byte UID magic MIFARE Classic card/fob
(USCUID/GDM-class) through an ACR122U. Reverse-engineered, byte-for-byte,
from a gap-free APDUPlay capture of the vendor "S50 7Byte UID Tool".

See the README for the full story. In short, "write" is a FOUR-phase session,
each phase its own fresh EXCLUSIVE connection, all via ACR122U Direct Transmit
(FF 00 00 00 Lc <PN532 frame>):

  phase 2  read + RF reset           (auth key A = FF*6, read block 0)
  phase 3  ARM: authenticated 'E0/E1' reads + '7A' gen-mode config write
           -> this is the step that lets the chip answer the backdoor knock;
              its effect is non-volatile and survives the reset. Without it,
              a byte-perfect knock returns D5 43 01 forever.
  phase 4  the actual write:
     1. backdoor entry : CRC off -> HALT (50 00) -> 7-bit '20' -> '23' -> CRC on
     2. vanity write   : D4 40 01  A0 00  <16 block-0 bytes>   (a reader READs this)
     3. live + config  : A8 00 / 88 <anticollision> / A8 01 / 6F.. / E1 00 /
                         85.. / E0 00   (what the card TRANSMITS), raw via
                         InCommunicateThru (D4 42), CRC off; then RF off/on.

Block 0 (vanity) and the live UID/SAK are stored SEPARATELY - that is what
makes the SAK-swap (vanity 88 / live 08) possible, the card's anti-clone trick.

It is pure SCardTransmit: no SCardControl, no transactions, no inter-frame
delays - a plain VB6 app on the same winscard + driver as this tool.

Commands:
  read            decode block 0 + report live SAK vs vanity SAK
  write <hex32>   arm, then full three-layer write, then verify

Requires: pip install pyscard
TEST ON A SPARE FOB. Close the vendor tool and any other reader software
first (EXCLUSIVE mode needs the reader free).
"""
import sys
import time
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.scard import (SCARD_SHARE_EXCLUSIVE, SCARD_SHARE_SHARED,
                             SCARD_RESET_CARD, SCARD_PROTOCOL_T0,
                             SCARD_PROTOCOL_T1)

__version__ = "4.2"

OK = (0x90, 0x00)
PROTO = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1   # vendor's SCardConnectA proto = 3

# Config frames, constant for this card model (verbatim from the capture).
CFG_6F = [0x6F, 0x31, 0x3D, 0x5F, 0x3C, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
CFG_85 = [0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x3C,
          0x00, 0x5A, 0x00, 0x5A, 0x00, 0x08]
# Phase-3 authenticated gen-mode config write - the "arm" step (from EA03).
ARM_7A = [0x7A, 0xFF, 0x85, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x5A,
          0x00, 0x5A, 0x00, 0x5A, 0x00, 0x08]


# ---- ISO14443A CRC_A (for raw InCommunicateThru frames) --------------------
def crc_a(data: bytes) -> bytes:
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# ---- reader plumbing -------------------------------------------------------
def get_reader():
    rs = readers()
    if not rs:
        sys.exit("No PC/SC reader found. Is the ACR122U plugged in?")
    for r in rs:
        if "ACR122" in str(r) or "ACS" in str(r):
            return r
    return rs[0]


def connect(timeout=20.0, settle=1.0):
    """EXCLUSIVE connection (so the Windows smart-card service doesn't poll the
    card mid-sequence), protocol pinned to T0|T1 to match the vendor.

    Waits out the 'card removed' (0x80100069) window that follows a write/reset
    while the reader re-detects the card. We retry GENTLY (1 s apart): hammering
    connect() in EXCLUSIVE mode keeps interrupting the reader's PICC poll cycle
    so it never completes a detection - the reader needs idle time to re-find
    the card (that's the delayed beep)."""
    last = None
    waited = 0.0
    notified = False
    while waited <= timeout:
        conn = get_reader().createConnection()
        try:
            conn.connect(mode=SCARD_SHARE_EXCLUSIVE, protocol=PROTO)
            return conn
        except Exception as e:
            last = e
            if waited >= 1.0 and not notified:
                print("# waiting for the reader to re-detect the card "
                      "(idle poll)...")
                notified = True
            time.sleep(settle)
            waited += settle
    try:                                 # last resort: shared mode
        conn = get_reader().createConnection()
        conn.connect(mode=SCARD_SHARE_SHARED, protocol=PROTO)
        return conn
    except Exception as e:
        last = e
    raise SystemExit(
        f"\nCould not connect to the card after {timeout:.0f}s.\n"
        "  - after a write the card must be RE-PRESENTED (lift it off the\n"
        "    reader and put it back) so the reader re-detects the new UID.\n"
        "  - is the fob on the reader, and the vendor tool closed?\n"
        "  - if it persists, a crashed run can wedge the ACR122U: UNPLUG and\n"
        f"    REPLUG the reader, then retry.\n  (last error: {last})")


def _close(conn):
    try:
        conn.disconnect(disposition=SCARD_RESET_CARD)
    except TypeError:
        try:
            conn.disconnect()
        except Exception:
            pass
    except Exception:
        pass


# ---- PN532 / ACR122U frame helpers -----------------------------------------
def transmit(conn, apdu):
    return conn.transmit(list(apdu))


def direct(conn, frame, label=""):
    """Wrap a PN532 frame in an ACR122U Direct Transmit pseudo-APDU."""
    apdu = [0xFF, 0x00, 0x00, 0x00, len(frame)] + list(frame)
    data, sw1, sw2 = transmit(conn, apdu)
    if (sw1, sw2) != OK:
        raise RuntimeError(f"reader error {sw1:02X}{sw2:02X} on {label!r}")
    return data  # PN532 response, starts with D5 ..


def reg_write(conn, pairs, label):
    frame = [0xD4, 0x08]
    for addr, val in pairs:
        frame += [(addr >> 8) & 0xFF, addr & 0xFF, val & 0xFF]
    direct(conn, frame, label)


def crc(conn, on):
    reg_write(conn, [(0x6302, 0x80 if on else 0x00),
                     (0x6303, 0x80 if on else 0x00)],
              f"CRC {'on' if on else 'off'}")


def bitframing(conn, bits):
    reg_write(conn, [(0x633D, bits)], f"bitframing={bits:02X}")


def rf_field(conn, on):
    direct(conn, [0xD4, 0x32, 0x01, 0x01 if on else 0x00],
           f"RF field {'on' if on else 'off'}")


def thru(conn, frame, add_crc=True, label="thru"):
    """InCommunicateThru (D4 42). Appends CRC_A unless add_crc=False.
    Caller must have CRC registers OFF."""
    f = list(frame)
    if add_crc:
        f += list(crc_a(bytes(frame)))
    return direct(conn, [0xD4, 0x42] + f, label)  # D5 43 <status> <data..>


def exchange(conn, frame, label="exchange"):
    """InDataExchange (D4 40, target 1). PN532 adds CRC + runs crypto.
    Caller must have CRC registers ON."""
    return direct(conn, [0xD4, 0x40, 0x01] + list(frame), label)


def get_uid(conn):
    data, sw1, sw2 = transmit(conn, [0xFF, 0xCA, 0x00, 0x00, 0x00])
    if (sw1, sw2) != OK:
        raise RuntimeError("could not read UID")
    return bytes(data)


def poll_info(conn):
    """InAutoPoll. Returns (atqa, live_sak, uid) or None."""
    r = direct(conn, [0xD4, 0x60, 0x01, 0x01, 0x20, 0x23, 0x11, 0x04, 0x10],
               "autopoll")
    if len(r) < 10 or r[0] != 0xD5 or r[1] != 0x61 or r[2] == 0:
        return None
    return bytes(r[6:8]), r[8], bytes(r[10:10 + r[9]])


def _auth_head(conn):
    """FF CA, autopoll, auth block 0 (key A = FF*6) on the card's current UID,
    then CRC off ready for raw thru frames. Shared by read and the arm phases."""
    uid = get_uid(conn)
    poll_info(conn)
    crc(conn, True)
    exchange(conn, [0x60, 0x00] + [0xFF] * 6 + list(uid[-4:]), "auth A blk0")
    crc(conn, False)


# ---- block 0 read ----------------------------------------------------------
def read_block0(conn):
    _auth_head(conn)
    resp = thru(conn, [0x30, 0x00], label="read blk0")
    crc(conn, True)
    return bytes(resp[3:19])


# ---- the full three-layer write --------------------------------------------
def build_88(uid, live_sak=0x08):
    """Live anticollision write. CL1: uid0-2, BCC1=88^uid0^uid1^uid2, SAK1=04.
    CL2: uid3-6, BCC2=xor, SAK2=live_sak. Then 4 pad bytes."""
    assert len(uid) == 7
    bcc1 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc2 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
    return [0x88,
            uid[0], uid[1], uid[2], bcc1, 0x04,
            uid[3], uid[4], uid[5], uid[6], bcc2, live_sak,
            0x00, 0x00, 0x00, 0x00]


def reset_card(conn):
    """Warm-reset the card WITHOUT releasing the handle (SCardReconnect,
    RESET_CARD). Gives the clean reset the knock needs between phases, but
    avoids the resource-manager 're-detect' gap (0x80100069) that a full
    disconnect/connect races after a reset."""
    try:
        conn.reconnect(mode=SCARD_SHARE_EXCLUSIVE, disposition=SCARD_RESET_CARD)
    except TypeError:
        conn.reconnect()


def arm(conn):
    """Vendor phase 2 (read + RF reset) then phase 3 (E0/E1 + the 7A gen-mode
    config write that arms the knock backdoor), on ONE held connection with a
    warm reset between phases. The 7A arm is non-volatile and survives into the
    write phase."""
    print("# arming: phase 2 (read)")
    _auth_head(conn)
    thru(conn, [0x30, 0x00], label="read blk0")
    crc(conn, True)
    rf_field(conn, False)
    rf_field(conn, True)
    reset_card(conn)

    print("# arming: phase 3 (E0/E1 + 7A)")
    _auth_head(conn)
    thru(conn, [0xE0, 0x00], label="E0 read")
    thru(conn, [0xE1, 0x00], label="E1 read")
    thru(conn, ARM_7A, label="7A gen-mode config (arm)")
    crc(conn, True)
    reset_card(conn)


def backdoor_write(conn, block0):
    """Phase 4: backdoor entry, vanity write, live + config writes. Requires an
    already-armed card (see arm())."""
    uid = block0[:7]
    get_uid(conn)

    # 1. backdoor entry
    crc(conn, False)
    thru(conn, [0x50, 0x00], label="halt")           # no ACK is normal for HALT
    bitframing(conn, 0x07)
    r = thru(conn, [0x20], add_crc=False, label="backdoor 20")
    if not (len(r) >= 3 and r[2] == 0x00):
        bitframing(conn, 0x00)
        crc(conn, True)
        rf_field(conn, False)           # recover the card from HALT so a later
        rf_field(conn, True)            # read isn't left talking to a dead card
        raise RuntimeError(
            f"backdoor '20' not ACKed (got {toHexString(list(r))}). "
            "The card was not armed - was the reader free and the fob present?")
    bitframing(conn, 0x00)
    thru(conn, [0x23], add_crc=False, label="backdoor 23")
    crc(conn, True)

    # 2. vanity write (block 0 memory a reader sees on READ).
    # D5 41 00 = InDataExchange success -> this is the authoritative write-OK
    # signal (the read-back verify is unreliable: the card's RF presence is
    # unstable right after a UID change, often needing a physical re-present).
    r = exchange(conn, [0xA0, 0x00] + list(block0), "A0 vanity write")
    vanity_ok = len(r) >= 3 and r[0] == 0xD5 and r[1] == 0x41 and r[2] == 0x00

    # 3. live + config writes (what the chip transmits in anticollision)
    crc(conn, False)
    thru(conn, [0xA8, 0x00], label="a8 00")
    thru(conn, build_88(uid), label="88 live UID/SAK")
    thru(conn, [0xA8, 0x01], label="a8 01")
    thru(conn, CFG_6F, label="6f config")
    thru(conn, [0xE1, 0x00], label="e1 00")
    thru(conn, CFG_85, label="85 config")
    thru(conn, [0xE0, 0x00], label="e0 00")

    # 4. RF reset, then CRC on (vendor tail order)
    rf_field(conn, False)
    rf_field(conn, True)
    crc(conn, True)
    return vanity_ok


def read_with_live(conn):
    """Block 0 + live SAK on an existing connection."""
    info = poll_info(conn)
    return read_block0(conn), (info[1] if info else None)


def write_block0(block0):
    """One held EXCLUSIVE connection for arm (phase 2+3) + write (phase 4).
    Success is taken from the write's own ACKs (knock + A0 'D5 41 00'), since
    the read-back is unreliable: after a UID change the card's RF presence is
    unstable and usually needs a physical re-present before it answers again.
    The verify is therefore best-effort - if the card has dropped off, we say
    so rather than fail."""
    assert len(block0) == 16
    conn = connect()
    wrote = False
    got, live = None, None
    try:
        arm(conn)                       # phase 2 + 3 (warm resets between)
        wrote = backdoor_write(conn, block0)
        try:                            # best-effort read-back on held handle
            time.sleep(0.2)
            reset_card(conn)
            got, live = read_with_live(conn)
        except Exception as e:
            print(f"# (auto-verify skipped: card dropped off after the write "
                  f"- {e.__class__.__name__}; this is normal)")
    finally:
        _close(conn)
    return wrote, got, live


# ---- presentation ----------------------------------------------------------
def decode_block0(b, live_sak=None):
    print(f"  block0 : {toHexString(list(b))}")
    print(f"  UID    : {toHexString(list(b[0:7]))}")
    print(f"  SAK    : {b[7]:02X}  (vanity / stored in block 0)")
    if live_sak is not None:
        print(f"  SAK    : {live_sak:02X}  (live / anticollision)")
        if live_sak != b[7]:
            print("           -> live != vanity  (SAK-swap present)")
    print(f"  ATQA   : {toHexString(list(b[8:10]))}")
    print(f"  manuf  : {toHexString(list(b[10:16]))}")


def main():
    args = sys.argv[1:]
    print(f"# fobtool {__version__}")
    if not args or args[0].lower() in ("-h", "--help", "help"):
        print(__doc__)
        print("usage: fobtool.py read")
        print("       fobtool.py write 04112233445566884400C82000000000")
        return
    cmd = args[0].lower()
    if cmd == "read":
        conn = connect()
        try:
            got, live = read_with_live(conn)
        finally:
            _close(conn)
        decode_block0(got, live)
    elif cmd == "write":
        if len(args) < 2:
            sys.exit("write needs 32 hex chars of block 0")
        hexstr = args[1].replace(" ", "")
        if len(hexstr) != 32:
            sys.exit("block 0 must be exactly 32 hex chars (16 bytes)")
        target = bytes.fromhex(hexstr)
        print("Target block 0:")
        decode_block0(target)
        wrote, got, live = write_block0(target)   # arms + writes (held conn)
        print("write OK" if wrote else "write FAILED")
        if got is None:
            print("(could not auto-verify - re-present the fob (lift it off and")
            print(" put it back) and run:  python fobtool.py read)")
        else:
            print("Verifying:")
            decode_block0(got, live)
            print("MATCH" if got == target else "MISMATCH")
    else:
        sys.exit(f"unknown command: {cmd!r} (use 'read' or 'write')")


if __name__ == "__main__":
    main()
