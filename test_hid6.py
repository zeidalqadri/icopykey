"""Direct Win32 HID I/O via ctypes — bypass hidapi entirely."""
import ctypes
import ctypes.wintypes
import time

GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROBE_IOCTL = 0x00B000E3  # IOCTL_HID_SET_OUTPUT_REPORT (Method NEITHER)

kernel32 = ctypes.windll.kernel32

# Get device path from hidapi
import hid
devices = hid.enumerate(0x6300, 0x1991)
if not devices:
    print("No device found")
    exit(1)

dev_path = devices[0]["path"].decode()
print(f"Device: {devices[0].get('product_string','')}")
print(f"Path: {dev_path}")

# Open with overlapped I/O (same as hidapi)
handle = kernel32.CreateFileW(
    dev_path,
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
print("Device opened via CreateFile")

# The full 64-byte frame from capture (first DEV_INFO exchange)
frame = bytes.fromhex(
    "958d84929b9c99b96205093d34222b2cf9c90742bae17c7a"
    "a3f76656008a50506240758700207a2f0f070e181116aa9a"
    "c0950c14dd765752b7a6682d0d05d8fc"
)

# Test 1: Overlapped WriteFile
print("\n--- Test 1: Overlapped WriteFile ---")
ol_write = ctypes.wintypes.OVERLAPPED()
ol_write.hEvent = kernel32.CreateEventW(None, True, False, None)

bytes_written = ctypes.wintypes.DWORD(0)
result = kernel32.WriteFile(
    handle,
    frame, 64,
    ctypes.byref(bytes_written),
    ctypes.byref(ol_write)
)

if not result:
    err = kernel32.GetLastError()
    if err == 997:  # ERROR_IO_PENDING
        print(f"  WriteFile pending, waiting...")
        ret = kernel32.WaitForSingleObject(ol_write.hEvent, 3000)
        if ret == 0:  # WAIT_OBJECT_0
            kernel32.GetOverlappedResult(handle, ctypes.byref(ol_write), ctypes.byref(bytes_written), False)
            print(f"  Write completed: {bytes_written.value} bytes")
        else:
            print(f"  Write timeout (wait returned {ret})")
            kernel32.CancelIo(handle)
    else:
        print(f"  WriteFile error: {err}")
else:
    print(f"  WriteFile completed synchronously: {bytes_written.value} bytes")

kernel32.CloseHandle(ol_write.hEvent)

# Test 2: Overlapped ReadFile
print("\n--- Test 2: Overlapped ReadFile (5s timeout) ---")
ol_read = ctypes.wintypes.OVERLAPPED()
ol_read.hEvent = kernel32.CreateEventW(None, True, False, None)

buf = (ctypes.c_uint8 * 64)()
bytes_read = ctypes.wintypes.DWORD(0)

result = kernel32.ReadFile(
    handle,
    buf, 64,
    ctypes.byref(bytes_read),
    ctypes.byref(ol_read)
)

if not result:
    err = kernel32.GetLastError()
    if err == 997:  # ERROR_IO_PENDING
        print(f"  ReadFile pending, waiting 5s...")
        ret = kernel32.WaitForSingleObject(ol_read.hEvent, 5000)
        if ret == 0:
            kernel32.GetOverlappedResult(handle, ctypes.byref(ol_read), ctypes.byref(bytes_read), False)
            actual = bytes(buf[:bytes_read.value])
            nz = sum(1 for b in actual if b != 0)
            print(f"  GOT DATA! {bytes_read.value}B, {nz} non-zero")
            if nz > 0:
                print(f"  Response: {actual.hex()}")
        else:
            print(f"  Read timeout ({ret})")
            kernel32.CancelIo(handle)
    else:
        print(f"  ReadFile error: {err}")
else:
    print(f"  ReadFile completed synchronously: {bytes_read.value} bytes")

kernel32.CloseHandle(ol_read.hEvent)

# Test 3: DeviceIoControl IOCTL_HID_SET_OUTPUT_REPORT
print("\n--- Test 3: IOCTL_HID_SET_OUTPUT_REPORT ---")
ol_ioctl = ctypes.wintypes.OVERLAPPED()
ol_ioctl.hEvent = kernel32.CreateEventW(None, True, False, None)

ioctl_buf = (ctypes.c_uint8 * 65)()
ioctl_buf[0] = 0  # Report ID
for i, b in enumerate(frame[:64]):
    ioctl_buf[i+1] = b

bytes_ret = ctypes.wintypes.DWORD(0)
result = kernel32.DeviceIoControl(
    handle,
    0x00B000E3,  # IOCTL_HID_SET_OUTPUT_REPORT
    ioctl_buf, 65,
    None, 0,
    ctypes.byref(bytes_ret),
    ctypes.byref(ol_ioctl)
)

if not result:
    err = kernel32.GetLastError()
    if err == 997:
        print(f"  IOCTL pending...")
        ret = kernel32.WaitForSingleObject(ol_ioctl.hEvent, 3000)
        if ret == 0:
            kernel32.GetOverlappedResult(handle, ctypes.byref(ol_ioctl), ctypes.byref(bytes_ret), False)
            print(f"  IOCTL completed: {bytes_ret.value}")
        else:
            print(f"  IOCTL timeout")
            kernel32.CancelIo(handle)
    else:
        print(f"  IOCTL error: {err}")
else:
    print(f"  IOCTL completed synchronously: {bytes_ret.value}")

kernel32.CloseHandle(ol_ioctl.hEvent)

# Test 4: Read again after IOCTL
print("\n--- Test 4: Read after IOCTL ---")
ol_read2 = ctypes.wintypes.OVERLAPPED()
ol_read2.hEvent = kernel32.CreateEventW(None, True, False, None)

result = kernel32.ReadFile(
    handle,
    buf, 64,
    ctypes.byref(bytes_read),
    ctypes.byref(ol_read2)
)

if not result:
    err = kernel32.GetLastError()
    if err == 997:
        print(f"  Read pending, waiting 5s...")
        ret = kernel32.WaitForSingleObject(ol_read2.hEvent, 5000)
        if ret == 0:
            kernel32.GetOverlappedResult(handle, ctypes.byref(ol_read2), ctypes.byref(bytes_read), False)
            actual = bytes(buf[:bytes_read.value])
            nz = sum(1 for b in actual if b != 0)
            print(f"  GOT DATA! {bytes_read.value}B, {nz} non-zero")
            if nz > 0:
                print(f"  Response: {actual.hex()}")
        else:
            print(f"  Read timeout")
            kernel32.CancelIo(handle)
    else:
        print(f"  ReadFile error: {err}")

kernel32.CloseHandle(ol_read2.hEvent)

kernel32.CloseHandle(handle)
print("\nDone")
