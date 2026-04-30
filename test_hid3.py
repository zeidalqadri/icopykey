import hid
import time

VID, PID = 0x6300, 0x1991

d = hid.device()
d.open_path(hid.enumerate(VID, PID)[0]["path"])
print(f"Product: {d.get_product_string()}")

d.set_nonblocking(True)

print("Polling for input reports for 15 seconds...")
print("While running, tap/remove card on the reader repeatedly.")
for i in range(30):
    resp = d.read(64, 2000)
    if resp:
        nz = sum(1 for b in resp if b != 0)
        if nz > 0:
            print(f"[{i}] GOT DATA! {nz} nz bytes: {bytes(resp).hex()}")
        else:
            print(f"[{i}] all zeros ({len(resp)} bytes)")
    else:
        print(f"[{i}] empty")
    time.sleep(0.5)

d.close()
