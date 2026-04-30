import hid
import time

REPORT_SIZE = 64
VID, PID = 0x6300, 0x1991

devices = hid.enumerate(VID, PID)
if not devices:
    print("No device found")
    exit(1)

path = devices[0]["path"]
print(f"Path: {path}")

d = hid.device()
d.open_path(path)
print(f"Product: {d.get_product_string()}")
print(f"Serial:  {d.get_serial_number_string()}")

# Test 1: send_feature_report (control pipe) then hid_read (interrupt IN)
# Feature report: first byte is report ID (0x00), then 64 bytes data
buf = b"\x00" + bytes([0x01]) + b"\x00" * 63  # 0x00 ID + GET_CARD_INFO padded
print(f"\nTest 1: send_feature_report({len(buf)}B)")
try:
    d.send_feature_report(buf)
    print("  send OK")
except Exception as e:
    print(f"  send error: {e}")

time.sleep(0.2)

d.set_nonblocking(True)
resp = d.read(64, 3000)
if resp:
    print(f"  hid_read: {len(resp)}B: {bytes(resp).hex()}")
else:
    print("  hid_read: empty")

# Test 2: send_feature_report with 0x8D (DEVICE_INFO)
buf = b"\x00" + bytes([0x8D]) + b"\x00" * 63
print(f"\nTest 2: send_feature_report DEV_INFO")
try:
    d.send_feature_report(buf)
    print("  send OK")
except Exception as e:
    print(f"  send error: {e}")

time.sleep(0.5)
resp = d.read(64, 3000)
if resp:
    print(f"  hid_read: {len(resp)}B: {bytes(resp).hex()}")
else:
    print("  hid_read: empty")

# Test 3: send_feature_report with 0x95 prefix proto
buf = b"\x00" + bytes.fromhex("958d84929b9c99b96205093d34222b2cf9c90742bae17c7aa3f76656008a5050")
buf = buf[:65]  # 0x00 + 64 bytes
print(f"\nTest 3: send_feature_report capture frame")
try:
    d.send_feature_report(buf)
    print("  send OK")
except Exception as e:
    print(f"  send error: {e}")

time.sleep(0.5)
resp = d.read(64, 3000)
if resp:
    print(f"  hid_read: {len(resp)}B: {bytes(resp).hex()}")
else:
    print("  hid_read: empty")

# Test 4: try hid_write with 64 bytes (interrupt OUT)
buf = bytes([0x8D]) + b"\x00" * 63
print(f"\nTest 4: hid_write 64B")
try:
    d.write(buf)
    print("  write OK")
except Exception as e:
    print(f"  write error: {e}")

time.sleep(0.5)
resp = d.read(64, 5000)
if resp:
    print(f"  hid_read: {len(resp)}B: {bytes(resp).hex()}")
else:
    print("  hid_read: empty")

d.close()
