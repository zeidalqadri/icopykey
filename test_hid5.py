import hid
import time
import sys

VID, PID = 0x6300, 0x1991

devices = hid.enumerate(VID, PID)
if not devices:
    print("No device found")
    sys.exit(1)

path = devices[0]["path"]
print(f"Path: {path}")

d = hid.device()
d.open_path(path)
print(f"Opened: {d.get_product_string()}")

# Exact first DEV_INFO frame from capture (full 64 bytes)
frame = bytes.fromhex(
    "958d84929b9c99b96205093d34222b2cf9c90742bae17c7a"
    "a3f76656008a50506240758700207a2f0f070e181116aa9a"
    "c0950c14dd765752b7a6682d0d05d8fc"
)
assert len(frame) == 64

# Test A: interrupt OUT (hid_write) + interrupt IN (hid_read)
print("\n═══ Test A: hid_write (interrupt OUT) ═══")
d.write(frame)
print("  Write OK")
time.sleep(0.1)

d.set_nonblocking(True)
resp = d.read(64, 5000)
if resp:
    actual = bytes(resp)
    nz = sum(1 for b in actual if b != 0)
    print(f"  Read: {len(resp)}B, {nz} non-zero")
    if nz > 0:
        print(f"  Response: {actual.hex()}")
else:
    print("  No response")

# Test B: send_feature_report (control pipe) + hid_read (interrupt IN)  
print("\n═══ Test B: send_feature_report (control) + hid_read ═══")
time.sleep(0.5)
try:
    # feature report needs report ID as first byte
    d.send_feature_report(b"\x00" + frame)
    print("  send_feature_report OK")
except Exception as e:
    print(f"  send_feature_report error: {e}")

time.sleep(0.1)
resp = d.read(64, 5000)
if resp:
    actual = bytes(resp)
    nz = sum(1 for b in actual if b != 0)
    print(f"  Read: {len(resp)}B, {nz} non-zero")
    if nz > 0:
        print(f"  Response: {actual.hex()}")
else:
    print("  No response")

# Test C: send_feature_report + get_input_report (both control pipe)
print("\n═══ Test C: send_feature_report + get_input_report (control) ═══")
time.sleep(0.5)
try:
    d.send_feature_report(b"\x00" + frame)
    print("  send_feature_report OK")
except Exception as e:
    print(f"  send_feature_report error: {e}")

time.sleep(0.1)
try:
    inp = d.get_input_report(0, 64)
    if inp:
        actual = bytes(inp)
        nz = sum(1 for b in actual if b != 0)
        print(f"  get_input_report: {len(inp)}B, {nz} non-zero")
        if nz > 0:
            print(f"  Response: {actual.hex()}")
    else:
        print("  get_input_report: empty")
except Exception as e:
    print(f"  get_input_report error: {e}")

# Test D: send_feature_report with zeros (control pipe)
print("\n═══ Test D: send_feature_report zeros (control) ═══")
time.sleep(0.5)
try:
    d.send_feature_report(b"\x00" + b"\x00" * 64)
    print("  send_feature_report OK")
except Exception as e:
    print(f"  send_feature_report error: {e}")

time.sleep(0.1)
resp = d.read(64, 5000)
if resp:
    actual = bytes(resp)
    nz = sum(1 for b in actual if b != 0)
    print(f"  Read: {len(resp)}B, {nz} non-zero")
    if nz > 0:
        print(f"  Response: {actual.hex()}")
else:
    print("  No response")

d.close()
