import ctypes
import ctypes.wintypes
import struct
from ctypes import byref, windll

# Windows HID API constants
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# IOCTL codes for HID
IOCTL_HID_SET_OUTPUT_REPORT = 0x00B000E3  # Method_NEITHER
IOCTL_HID_GET_INPUT_REPORT = 0x00B000EB  # Method_NEITHER  
IOCTL_HID_SET_FEATURE = 0x00B000E1  # METHOD_NEITHER
IOCTL_HID_GET_FEATURE = 0x00B000E9  # METHOD_NEITHER

# Device path (CopyKEY X100)
DEV_PATH = r"\\.\HID#VID_6300&PID_1991#6&2b7fcfee&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"

kernel32 = windll.kernel32

# Open HID device
handle = kernel32.CreateFileA(
    DEV_PATH.encode(),
    GENERIC_WRITE | GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,
    None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"CreateFile failed: {kernel32.GetLastError()}")
    exit(1)

print("Device opened")

# Build IOCTL_HID_SET_OUTPUT_REPORT
buf_size = 65  # 1 byte report ID (0) + 64 raw bytes
buf = (ctypes.c_uint8 * buf_size)()
buf[0] = 0  # Report ID = 0 for no-ID device
buf[1] = 0x95  # 0x95 prefix
# rest is zeros

bytes_ret = ctypes.wintypes.DWORD(0)

# Test 1: IOCTL_HID_SET_OUTPUT_REPORT
print("\nTest 1: IOCTL_HID_SET_OUTPUT_REPORT (0x95 prefix, zeros)")
result = kernel32.DeviceIoControl(
    handle,
    IOCTL_HID_SET_OUTPUT_REPORT,
    buf, buf_size,
    None, 0,
    byref(bytes_ret),
    None
)
print(f"  DeviceIoControl: {bool(result)}, bytes_ret={bytes_ret.value}")

# Test 2: IOCTL_HID_SET_FEATURE
print("\nTest 2: IOCTL_HID_SET_FEATURE (0x95 prefix, zeros)")
result = kernel32.DeviceIoControl(
    handle,
    IOCTL_HID_SET_FEATURE,
    buf, buf_size,
    None, 0,
    byref(bytes_ret),
    None
)
print(f"  DeviceIoControl: {bool(result)}, bytes_ret={bytes_ret.value}")

# Test 3: WriteFile (interrupt OUT)
print("\nTest 3: WriteFile interrupt OUT (64 bytes no report ID)")
out_buf = (ctypes.c_uint8 * 64)()
for i, b in enumerate(bytes.fromhex("958d84929b9c99b96205093d34222b2cf9c90742bae17c7aa3f76656008a5050")):
    if i < 64:
        out_buf[i] = b

result = kernel32.WriteFile(handle, out_buf, 64, byref(bytes_ret), None)
print(f"  WriteFile: {bool(result)}, written={bytes_ret.value}")
if not result:
    print(f"  Error: {kernel32.GetLastError()}")

# Test 4: ReadFile (interrupt IN)
print("\nTest 4: ReadFile interrupt IN (5 second timeout)")
in_buf = (ctypes.c_uint8 * 64)()
result = kernel32.ReadFile(handle, in_buf, 64, byref(bytes_ret), None)
if result:
    actual = bytes(in_buf[:bytes_ret.value])
    nz = sum(1 for b in actual if b != 0)
    print(f"  ReadFile: OK, read={bytes_ret.value}, nz={nz}")
    if nz > 0:
        print(f"  data: {actual[:32].hex()}")
else:
    err = kernel32.GetLastError()
    print(f"  ReadFile: err={err} (this is normal if pending)")
    if err == 997:  # ERROR_IO_PENDING
        # Wait with overlapped
        import time
        time.sleep(5)
        # Check result
        overlapped = ctypes.wintypes.OVERLAPPED()
        result = kernel32.GetOverlappedResult(handle, byref(overlapped), byref(bytes_ret), True)
        if result:
            actual = bytes(in_buf[:bytes_ret.value])
            print(f"  Got data: {bytes_ret.value} bytes - {actual[:32].hex()}")
        else:
            kernel32.CancelIo(handle)
            print(f"  No data after 5s")

kernel32.CloseHandle(handle)
