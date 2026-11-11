#!/usr/bin/env python3
"""Linux integration regressions: sudo python3 scripts/netem/test_ns_exec.py.

Uses one owned namespace and a 64 MiB cgroup; no traffic or Sail build.
All launched children have bounded timeouts and all owned state is removed.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run = load("netem_run", HERE / "run.py")
launcher = load("netem_ns_exec", HERE / "ns_exec.py")
SNAPSHOT = r'''
import json,os,pathlib,sys
root=pathlib.Path('/sys/fs/cgroup')
placed=pathlib.Path('/proc/self/cgroup').read_text().strip().split('::',1)[-1]
def read(p):
 try:return pathlib.Path(p).read_text()
 except OSError:return None
fds={}
for fd in pathlib.Path('/proc/self/fd').iterdir():
 try:fds[fd.name]=os.readlink(fd)
 except OSError:pass
print(json.dumps({'pid':os.getpid(),'cgroup':placed,'limit':read(root/placed.lstrip('/')/'memory.max'),'controllers':read(root/'cgroup.controllers'),'resolv':read('/etc/resolv.conf'),'hosts':read('/etc/hosts'),'interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),'affinity':sorted(os.sched_getaffinity(0)),'args':sys.argv[1:],'fds':fds}))
'''


class MountDetection(unittest.TestCase):
    def test_v2_and_nested_v1_mounts(self):
        for path, kind in [("/sys/fs/cgroup", "cgroup2"),
                           ("/sys/fs/cgroup/memory", "cgroup"),
                           (r"/sys/fs/cgroup/a\040b", "cgroup")]:
            self.assertTrue(launcher.cgroup_mounted(
                f"1 2 0:1 / {path} rw - {kind} cgroup rw\n"))
        for path, kind in [("/sys/fs/cgroup-else", "cgroup2"),
                           ("/somewhere", "cgroup"), ("/sys/fs/cgroup", "tmpfs")]:
            self.assertFalse(launcher.cgroup_mounted(
                f"1 2 0:1 / {path} rw - {kind} cgroup rw\n"))

    def test_unavailable_clone_api_does_not_launch_a_workload(self):
        mountinfo = "1 2 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
        with patch("builtins.open", return_value=io.StringIO(mountinfo)), \
                patch.object(launcher, "clone_cgroups", side_effect=OSError(38, "unavailable")), \
                patch.object(launcher.os, "execvp") as execute:
            with self.assertRaises(OSError):
                launcher.main(["test-namespace", "--", "must-not-execute"])
            execute.assert_not_called()

    def test_same_namespace_is_rejected_before_any_mount(self):
        if not Path("/proc/self/ns/mnt").exists():
            self.skipTest("Linux mount namespace required")
        fd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
        try:
            with patch.object(launcher, "mount") as mount:
                with self.assertRaisesRegex(RuntimeError, "original mount namespace"):
                    launcher.restore(fd, fd)
                mount.assert_not_called()
        finally:
            os.close(fd)


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "Linux root with network/mount namespace privileges required")
class NamespaceIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tag = "sail-netem-test-" + str(os.getpid()) + "-" + uuid.uuid4().hex[:6]
        cls.cg = Path("/sys/fs/cgroup") / cls.tag
        cls.etc = Path("/etc/netns") / cls.tag
        cls.created_ns = cls.created_cg = cls.created_etc = cls.created_parent = False
        cls.temp = tempfile.TemporaryDirectory(prefix="sail-netem-test-")
        cls.resolv = "# " + cls.tag + "\nnameserver 192.0.2.53\n"
        cls.hosts = "127.0.0.1 localhost\n192.0.2.54 " + cls.tag + "\n"
        try:
            if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
                raise unittest.SkipTest("writable cgroup v2 memory controller required")
            cls.cg.mkdir(); cls.created_cg = True
            (cls.cg / "memory.max").write_text(str(64 << 20))
            (cls.cg / "memory.swap.max").write_text("0")
            subprocess.run(["ip", "netns", "add", cls.tag], check=True, timeout=5)
            cls.created_ns = True
            subprocess.run(["ip", "-n", cls.tag, "link", "add", "netem-test0", "type", "dummy"],
                           check=True, timeout=5)
            if not cls.etc.parent.exists():
                cls.etc.parent.mkdir(); cls.created_parent = True
            cls.etc.mkdir(); cls.created_etc = True
            (cls.etc / "resolv.conf").write_text(cls.resolv)
            (cls.etc / "hosts").write_text(cls.hosts)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.created_ns:
            # A failed assertion must not leave a workload retaining this ns.
            pids = subprocess.check_output(["ip", "netns", "pids", cls.tag], text=True,
                                           timeout=5).split()
            for pid in pids:
                try: os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError: pass
            subprocess.run(["ip", "netns", "del", cls.tag], check=True, timeout=5)
        if cls.created_etc:
            (cls.etc / "resolv.conf").unlink(); (cls.etc / "hosts").unlink(); cls.etc.rmdir()
        if cls.created_parent:
            cls.etc.parent.rmdir()
        if cls.created_cg:
            for _ in range(100):
                try: cls.cg.rmdir(); break
                except OSError:
                    time.sleep(.01)
            else: cls.cg.rmdir()
        cls.temp.cleanup()

    def enter_cgroup(self):
        (self.cg / "cgroup.procs").write_text(str(os.getpid()))

    def execute(self, command, **kwargs):
        before = Path("/proc/self/mountinfo").read_text()
        result = subprocess.run(command, shell=True, text=True, capture_output=True,
                                preexec_fn=self.enter_cgroup, timeout=10, **kwargs)
        self.assertEqual(before, Path("/proc/self/mountinfo").read_text(),
                         "launcher changed the parent's mount namespace")
        return result

    def snapshot(self, helper=run.in_ns, args=()):
        result = self.execute(helper(self.tag, shlex.join([sys.executable, "-c", SNAPSHOT, *args])))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_namespace_contract(self, value):
        self.assertIsNotNone(value["limit"], "namespace helper hid the cgroup limit")
        self.assertEqual(value["limit"].strip(), str(64 << 20))
        self.assertIn("memory", value["controllers"])
        self.assertEqual(value["resolv"], self.resolv)
        self.assertEqual(value["hosts"], self.hosts)
        self.assertEqual(value["interfaces"], ["lo", "netem-test0"])
        self.assertEqual(value["cgroup"], "/" + self.tag)
        # Inherited pinning descriptors must not reach the workload.
        self.assertEqual(set(value["fds"]), {"0", "1", "2"})

    def test_actual_helpers_preserve_cgroup_dns_hosts_and_sysfs(self):
        for helper in (run.in_ns, run.in_ns_netgen):
            with self.subTest(helper=helper.__name__):
                self.assert_namespace_contract(self.snapshot(helper))

    def test_old_helper_loses_cgroups_and_nsenter_loses_dns_sysfs(self):
        cmd = shlex.join([sys.executable, "-c", SNAPSHOT])
        old = self.execute(shlex.join(["ip", "netns", "exec", self.tag]) + " " + cmd)
        self.assertEqual(old.returncode, 0, old.stderr)
        value = json.loads(old.stdout)
        self.assertIsNone(value["limit"])
        self.assertEqual(value["resolv"], self.resolv)
        self.assertEqual(value["hosts"], self.hosts)
        self.assertEqual(value["interfaces"], ["lo", "netem-test0"])
        control = self.execute(shlex.join(["nsenter", "--net=/var/run/netns/" + self.tag]) + " " + cmd)
        self.assertEqual(control.returncode, 0, control.stderr)
        value = json.loads(control.stdout)
        self.assertEqual(value["limit"].strip(), str(64 << 20))
        self.assertNotEqual(value["resolv"], self.resolv)
        self.assertNotIn("netem-test0", value["interfaces"])

    def test_quoting_paths_arguments_and_exit_status(self):
        # Exercise the generated prefix itself from a path containing shell syntax.
        path = Path(self.temp.name) / "launcher's copy ; $.py"
        path.write_bytes((HERE / "ns_exec.py").read_bytes())
        args = ["a b", "single'quote", 'double"quote', "$literal;`literal`", ""]
        with patch.object(run, "NS_EXEC", str(path)):
            value = self.snapshot(args=args)
            self.assert_namespace_contract(value)
            self.assertEqual(value["args"], args)
        result = self.execute(run.in_ns(self.tag, shlex.join([sys.executable, "-c", "import sys;sys.exit(37)"])))
        self.assertEqual(result.returncode, 37)

    def test_cpu_pinning_and_netgen_override(self):
        cpus = sorted(os.sched_getaffinity(0))
        one, other = str(cpus[0]), str(cpus[-1])
        with patch.dict(run.CPUS, {self.tag: one}, clear=True), patch.dict(run.NETGEN_CPUS, {}, clear=True):
            self.assertEqual(self.snapshot()["affinity"], [cpus[0]])
            self.assertEqual(self.snapshot(run.in_ns_netgen)["affinity"], [cpus[0]])
            with patch.dict(run.NETGEN_CPUS, {self.tag: other}):
                self.assertEqual(self.snapshot(run.in_ns_netgen)["affinity"], [cpus[-1]])

    def test_proc_samples_workload_pid_and_stops_its_group(self):
        fixture = Path(self.temp.name) / "wait.py"
        ready, stopped = Path(self.temp.name) / "ready", Path(self.temp.name) / "stopped"
        fixture.write_text("import os,pathlib,signal,sys\n"
                           "def stop(*args):\n pathlib.Path(sys.argv[2]).write_text('TERM');sys.exit(0)\n"
                           "signal.signal(signal.SIGTERM,stop)\n"
                           "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                           "signal.pause()\n")
        before = Path("/proc/self/mountinfo").read_text()
        proc = run.Proc("pid-test", self.tag,
                        shlex.join([sys.executable, str(fixture), str(ready), str(stopped)]),
                        str(Path(self.temp.name) / "proc.log"))
        try:
            for _ in range(150):
                if ready.exists(): break
                self.assertTrue(proc.alive(), "launcher exited before workload")
                time.sleep(.02)
            self.assertTrue(ready.exists(), "workload did not start")
            pid = int(ready.read_text())
            self.assertEqual(proc.pid(), pid, "sampler sees a waiting launcher instead of workload")
        finally:
            proc.stop()
        self.assertTrue(stopped.exists(), "workload did not receive process-group SIGTERM")
        self.assertEqual(before, Path("/proc/self/mountinfo").read_text())

    def private_fixture(self, setup, payload):
        # unshare establishes a disposable mount namespace BEFORE fixture
        # mounts. Their paths are never mounted in the test runner's ns.
        code = ("import os,pathlib,subprocess,sys\n" + setup +
                "os.execv(sys.executable," + repr([sys.executable, str(HERE / "ns_exec.py"),
                                                  self.tag, "--", sys.executable, "-c", payload]) + ")\n")
        return self.execute(shlex.join(["unshare", "--mount", "--propagation", "private",
                                        sys.executable, "-c", code]))

    def test_no_cgroup_mount_keeps_original_launch_contract(self):
        result = self.private_fixture(
            "subprocess.run(['umount','-R','/sys/fs/cgroup'],check=True)\n", SNAPSHOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertIsNone(value["limit"])
        self.assertIsNone(value["controllers"])
        self.assertEqual(value["resolv"], self.resolv)
        self.assertEqual(value["hosts"], self.hosts)
        self.assertEqual(value["interfaces"], ["lo", "netem-test0"])
        self.assertEqual(set(value["fds"]), {"0", "1", "2"})

    def test_recursive_clone_preserves_readonly_controller_like_submount(self):
        source = Path(self.temp.name) / "original-cgroups"
        source.mkdir()
        setup = ("source=" + repr(str(source)) + "\n"
                 "subprocess.run(['mount','--bind','/sys/fs/cgroup',source],check=True)\n"
                 "subprocess.run(['mount','-t','tmpfs','-o','size=64k','tmpfs','/sys/fs/cgroup'],check=True)\n"
                 "pathlib.Path('/sys/fs/cgroup/memory').mkdir()\n"
                 "subprocess.run(['mount','--bind',source,'/sys/fs/cgroup/memory'],check=True)\n"
                 "subprocess.run(['mount','-o','remount,bind,ro','/sys/fs/cgroup/memory'],check=True)\n"
                 "subprocess.run(['mount','--make-rshared','/sys/fs/cgroup'],check=True)\n")
        payload = ("import json,pathlib\n"
                   "p=pathlib.Path('/sys/fs/cgroup/memory')\n"
                   "lines=pathlib.Path('/proc/self/mountinfo').read_text().splitlines()\n"
                   "mounts=[s.split(' - ')[0].split() for s in lines if ' /sys/fs/cgroup' in s]\n"
                   "print(json.dumps({'limit':(p/" + repr(self.tag) + "/'memory.max').read_text(),"
                   "'readonly':bool(__import__('os').statvfs(p).f_flag & __import__('os').ST_RDONLY),"
                   "'mounts':mounts}))\n")
        result = self.private_fixture(setup, payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["limit"].strip(), str(64 << 20))
        self.assertTrue(value["readonly"], "controller's read-only mount flag was lost")
        self.assertTrue(any(m[4] == "/sys/fs/cgroup/memory" for m in value["mounts"]))
        self.assertFalse(any(f.startswith(("shared:", "master:"))
                             for m in value["mounts"] for f in m[6:]),
                         "restored tree retains propagation peers")

    def test_real_syscall_fallback_preserves_actual_limited_cgroup(self):
        if launcher.platform.machine() not in ("x86_64", "aarch64") or \
                launcher.ctypes.sizeof(launcher.ctypes.c_void_p) != 8:
            self.skipTest("raw syscall fallback supports only 64-bit x86_64/aarch64")
        # Hide only the libc wrappers, forwarding the real syscall and mount
        # symbols. Both stages use the production functions; no injected
        # production flag or synthetic syscall result can satisfy this test.
        bootstrap = ("import ctypes,importlib.util,json,os,pathlib,subprocess,sys\n"
                     "spec=importlib.util.spec_from_file_location('ns_exec'," +
                     repr(str(HERE / "ns_exec.py")) + ")\n"
                     "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n"
                     "real=ctypes.CDLL(None,use_errno=True);hidden=[]\n"
                     "class WithoutWrappers:\n"
                     " def __getattr__(self,name):\n"
                     "  if name in ('open_tree','move_mount'):\n"
                     "   hidden.append(name);raise AttributeError(name)\n"
                     "  return getattr(real,name)\n"
                     "module.ctypes.CDLL=lambda *args,**kwargs:WithoutWrappers()\n")
        child = (bootstrap +
                 "module.restore(int(sys.argv[1]),int(sys.argv[2]))\n"
                 "print(json.dumps({'limit':pathlib.Path('/sys/fs/cgroup/" + self.tag +
                 "/memory.max').read_text(),'hidden':hidden}))\n")
        parent = (bootstrap +
                  "before=pathlib.Path('/proc/self/mountinfo').read_text()\n"
                  "tree=module.clone_cgroups();ns=os.open('/proc/self/ns/mnt',os.O_RDONLY)\n"
                  "try:\n"
                  " result=subprocess.run(" + repr(["ip", "netns", "exec", self.tag,
                                                       sys.executable, "-c", child]) +
                  "+[str(tree),str(ns)],pass_fds=(tree,ns),text=True,capture_output=True,timeout=5,check=True)\n"
                  " value=json.loads(result.stdout);value['parent_hidden']=hidden\n"
                  " assert before==pathlib.Path('/proc/self/mountinfo').read_text()\n"
                  " print(json.dumps(value))\n"
                  "finally:\n os.close(tree);os.close(ns)\n")
        result = self.execute(shlex.join(["unshare", "--mount", "--propagation", "private",
                                         sys.executable, "-c", parent]))
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["limit"].strip(), str(64 << 20))
        self.assertEqual(value["parent_hidden"], ["open_tree"])
        self.assertEqual(value["hidden"], ["move_mount"])

    def test_restore_failure_never_execs_workload(self):
        # An invalid pinned descriptor fails before the workload is execed.
        marker = Path(self.temp.name) / "must-not-exist"
        nsfd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
        try:
            command = ["ip", "netns", "exec", self.tag, sys.executable, str(HERE / "ns_exec.py"),
                       "--restore", "999999", str(nsfd), "--", sys.executable, "-c",
                       "from pathlib import Path;Path(" + repr(str(marker)) + ").touch()"]
            before = Path("/proc/self/mountinfo").read_text()
            result = subprocess.run(command, pass_fds=(nsfd,), capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("namespace launch failed", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(before, Path("/proc/self/mountinfo").read_text())
        finally:
            os.close(nsfd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
