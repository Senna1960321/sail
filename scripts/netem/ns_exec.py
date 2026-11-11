#!/usr/bin/env python3
"""Run in an ip-netns namespace without hiding the caller's cgroups.

ip netns exec supplies per-namespace /etc files and network sysfs, but its
fresh /sys hides the inherited cgroup mounts. Pin their original tree
before exec, then restore it only in ip's new mount namespace. Every stage
execs its successor: the workload remains the process sampled/signalled by
run.py, without an extra waiting launcher.
"""
import ctypes
import errno
import os
import platform
import re
import sys

CGROUP_ROOT = "/sys/fs/cgroup"
MS_REC = 16384
MS_PRIVATE = 1 << 18
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
OPEN_TREE_CLONE = 1
MOVE_MOUNT_F_EMPTY_PATH = 4


def cgroup_mounted(text):
    """A v2 mount, or v1 controller submounts, under the expected root."""
    for line in text.splitlines():
        before, sep, after = line.partition(" - ")
        fields = before.split()
        if not sep or len(fields) < 5:
            continue
        path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        kind = after.split()[0]
        if kind in ("cgroup", "cgroup2") and (
                path == CGROUP_ROOT or path.startswith(CGROUP_ROOT + "/")):
            return True
    return False


def mount(source, target, flags):
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.mount
    call.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                     ctypes.c_ulong, ctypes.c_void_p)
    call.restype = ctypes.c_int
    if call(os.fsencode(source) if source else None, os.fsencode(target),
            None, flags, None):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def mount_api(name, number, types, args):
    """libc wrappers where available; Linux's generic syscall ABI otherwise."""
    libc = ctypes.CDLL(None, use_errno=True)
    call = getattr(libc, name, None)
    if call is None:
        # Linux UAPI asm-generic/unistd.h and x86 syscall_64.tbl assign
        # these numbers on 64-bit aarch64/x86_64. Other ABIs need wrappers.
        if ctypes.sizeof(ctypes.c_void_p) != 8 or platform.machine() not in ("x86_64", "aarch64"):
            raise RuntimeError(f"libc {name} wrapper required on this architecture")
        call = libc.syscall
        types, args = (ctypes.c_long, *types), (number, *args)
        call.restype = ctypes.c_long
    else:
        call.restype = ctypes.c_int
    call.argtypes = types
    result = call(*args)
    if result < 0:
        error = ctypes.get_errno()
        hint = " (Linux >= 5.2 required)" if error == errno.ENOSYS else ""
        raise OSError(error, f"{name}: {os.strerror(error)}{hint}")
    return result


def clone_cgroups():
    # A plain O_PATH descriptor belongs to the original mount namespace:
    # binding from it after ip changes namespaces fails with EINVAL. Clone
    # a detached mount tree instead, specifically made to cross that boundary.
    return mount_api("open_tree", 428,
                     (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint),
                     (AT_FDCWD, os.fsencode(CGROUP_ROOT),
                      OPEN_TREE_CLONE | os.O_CLOEXEC | AT_RECURSIVE))


def restore(cgroup_fd, namespace_fd):
    old = os.fstat(namespace_fd)
    current = os.stat("/proc/self/ns/mnt")
    if (old.st_dev, old.st_ino) == (current.st_dev, current.st_ino):
        raise RuntimeError("refusing to restore cgroups in the original mount namespace")
    # A new namespace alone does not prevent propagation through shared
    # mounts. Make this already separate tree private before attaching.
    mount(None, "/", MS_REC | MS_PRIVATE)
    # Move the recursive clone, keeping v1 controller submounts and their
    # original flags (including read-only). No new cgroup hierarchy is made.
    mount_api("move_mount", 429,
              (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
               ctypes.c_char_p, ctypes.c_uint),
              (cgroup_fd, b"", AT_FDCWD, os.fsencode(CGROUP_ROOT),
               MOVE_MOUNT_F_EMPTY_PATH))
    # A recursive clone can retain the source mounts' propagation types.
    # Detach those peer relationships before the workload touches the tree.
    mount(None, CGROUP_ROOT, MS_REC | MS_PRIVATE)
    original = os.fstat(cgroup_fd)
    restored = os.stat(CGROUP_ROOT)
    if (original.st_dev, original.st_ino) != (restored.st_dev, restored.st_ino):
        raise RuntimeError("restored cgroup root does not match the pinned tree")


def main(argv):
    if argv[:1] == ["--restore"]:
        if len(argv) < 5 or argv[3] != "--":
            raise ValueError("invalid cgroup restore arguments")
        cgroup_fd, namespace_fd = int(argv[1]), int(argv[2])
        try:
            restore(cgroup_fd, namespace_fd)
        finally:
            os.close(cgroup_fd)
            os.close(namespace_fd)
        os.execvp(argv[4], argv[4:])
    if len(argv) < 3 or argv[1] != "--":
        raise ValueError("usage: ns_exec.py NAMESPACE -- COMMAND [ARG ...]")
    namespace, command = argv[0], argv[2:]
    with open("/proc/self/mountinfo") as source:
        mounted = cgroup_mounted(source.read())
    if not mounted:
        os.execvp("ip", ["ip", "netns", "exec", namespace, *command])
    cgroup_fd = clone_cgroups()
    namespace_fd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
    try:
        # exec-chain, including ip, intentionally inherits exactly these
        # two descriptors. Close them before execing the actual workload.
        os.set_inheritable(cgroup_fd, True)
        os.set_inheritable(namespace_fd, True)
        os.execvp("ip", ["ip", "netns", "exec", namespace, sys.executable,
                         os.path.abspath(__file__), "--restore", str(cgroup_fd),
                         str(namespace_fd), "--", *command])
    finally:
        os.close(cgroup_fd)
        os.close(namespace_fd)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(f"netem namespace launch failed: {error}")
