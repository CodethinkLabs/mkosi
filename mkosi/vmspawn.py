import asyncio
import base64
import contextlib
import enum
import hashlib
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import (
    ConfigFeature,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
    format_bytes,
)
from mkosi.log import die
from mkosi.partition import finalize_root, find_partitions
from mkosi.run import MkosiAsyncioThread, run, spawn
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import INVOKING_USER, StrEnum
from mkosi.qemu import (
    QemuDeviceNode,
    KernelType,
    find_ovmf_vars,
    find_qemu_binary,
    find_ovmf_firmware,
    vsock_notify_handler,
    start_swtpm,
    start_virtiofsd,
    machine_cid,
    copy_ephemeral
)

def run_vmspawn(args: MkosiArgs, config: MkosiConfig, qemu_device_fds: Mapping[QemuDeviceNode, int]) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.cpio, OutputFormat.uki, OutputFormat.directory):
        die(f"{config.output_format} images cannot be booted in qemu")

    if (
        config.output_format in (OutputFormat.cpio, OutputFormat.uki) and
        config.qemu_firmware not in (QemuFirmware.auto, QemuFirmware.linux, QemuFirmware.uefi)
    ):
        die(f"{config.output_format} images cannot be booted with the '{config.qemu_firmware}' firmware")

    if (config.runtime_trees and config.qemu_firmware == QemuFirmware.bios):
        die("RuntimeTrees= cannot be used when booting in BIOS firmware")

    if config.qemu_kvm == ConfigFeature.enabled and not QemuDeviceNode.kvm.available():
        die("KVM acceleration requested but cannot access /dev/kvm")

    if config.qemu_vsock == ConfigFeature.enabled and QemuDeviceNode.vhost_vsock not in qemu_device_fds:
        die("VSock requested but cannot access /dev/vhost-vsock")

    accel = "tcg"
    auto = (
        config.qemu_kvm == ConfigFeature.auto and
        config.architecture.is_native() and
        QemuDeviceNode.kvm.available()
    )
    if config.qemu_kvm == ConfigFeature.enabled or auto:
        accel = "kvm"

    if config.qemu_kernel:
        kernel = config.qemu_kernel
    elif "-kernel" in args.cmdline:
        kernel = Path(args.cmdline[args.cmdline.index("-kernel") + 1])
    else:
        kernel = None

    if config.output_format == OutputFormat.uki and kernel:
        logging.warning(
            f"Booting UKI output, kernel {kernel} configured with QemuKernel= or passed with -kernel will not be used"
        )
        kernel = None

    if kernel and not kernel.exists():
        die(f"Kernel not found at {kernel}")

    if config.qemu_firmware == QemuFirmware.auto:
        if kernel:
            firmware = QemuFirmware.uefi if KernelType.identify(kernel) != KernelType.unknown else QemuFirmware.linux
        elif (
            config.output_format in (OutputFormat.cpio, OutputFormat.directory) or
            config.architecture.to_efi() is None
        ):
            firmware = QemuFirmware.linux
        else:
            firmware = QemuFirmware.uefi
    else:
        firmware = config.qemu_firmware

    if (
        firmware == QemuFirmware.linux or
        config.output_format in (OutputFormat.cpio, OutputFormat.directory, OutputFormat.uki)
    ):
        if firmware == QemuFirmware.uefi:
            name = config.output if config.output_format == OutputFormat.uki else config.output_split_uki
            kernel = config.output_dir_or_cwd() / name
        else:
            kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}, please install a kernel in the image "
                "or provide a -kernel argument to mkosi qemu"
            )

    ovmf, ovmf_supports_sb = find_ovmf_firmware(config) if firmware == QemuFirmware.uefi else (None, False)

    # A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd.
    shm = []
    if config.runtime_trees or config.output_format == OutputFormat.directory:
        shm = ["-object", f"memory-backend-memfd,id=mem,size={config.qemu_mem},share=on"]

    if config.architecture == Architecture.arm64:
        machine = f"type=virt,accel={accel}"
    else:
        machine = f"type=q35,accel={accel},smm={'on' if ovmf_supports_sb else 'off'}"

    if shm:
        machine += ",memory-backend=mem"

    cmdline: list[PathString] = [
        find_qemu_binary(config),
        "-machine", machine,
        "-smp", config.qemu_smp,
        "-m", config.qemu_mem,
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
        "-nic", "user,model=virtio-net-pci",
        *shm,
    ]

    if QemuDeviceNode.vhost_vsock in qemu_device_fds:
        cmdline += [
            "-device",
            f"vhost-vsock-pci,guest-cid={machine_cid(config)},vhostfd={qemu_device_fds[QemuDeviceNode.vhost_vsock]}"
        ]

    cmdline += ["-cpu", "max"]

    if config.qemu_gui:
        cmdline += ["-vga", "virtio"]
    else:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += [
            "-nographic",
            "-nodefaults",
            "-chardev", "stdio,mux=on,id=console,signal=off",
            "-serial", "chardev:console",
            "-mon", "console",
        ]

    if config.architecture.supports_smbios():
        for k, v in config.credentials.items():
            payload = base64.b64encode(v.encode()).decode()
            cmdline += [
                "-smbios", f"type=11,value=io.systemd.credential.binary:{k}={payload}"
            ]

    # QEMU has built-in logic to look for the BIOS firmware so we don't need to do anything special for that.
    if firmware == QemuFirmware.uefi:
        cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={ovmf}"]
    notifications: dict[str, str] = {}

    with contextlib.ExitStack() as stack:
        if firmware == QemuFirmware.uefi and ovmf_supports_sb:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix="mkosi-ovmf-vars"))
            shutil.copy2(find_ovmf_vars(config), Path(ovmf_vars.name))
            # Make sure qemu can access the ephemeral vars.
            os.chown(ovmf_vars.name, INVOKING_USER.uid, INVOKING_USER.gid)
            cmdline += [
                "-global", "ICH9-LPC.disable_s3=1",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-drive", f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.qemu_cdrom and config.output_format == OutputFormat.disk:
            # CD-ROM devices have sector size 2048 so we transform the disk image into one with sector size 2048.
            src = (config.output_dir_or_cwd() / config.output).resolve()
            fname = src.parent / f"{src.name}-{uuid.uuid4().hex}"
            run(["systemd-repart",
                 "--definitions", "",
                 "--no-pager",
                 "--pretty=no",
                 "--offline=yes",
                 "--empty=create",
                 "--size=auto",
                 "--sector-size=2048",
                 "--copy-from", src,
                 fname])
            stack.callback(lambda: fname.unlink())
        elif config.ephemeral and config.output_format not in (OutputFormat.cpio, OutputFormat.uki):
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = config.output_dir_or_cwd() / config.output

        # Make sure qemu can access the ephemeral copy. Not required for directory output because we don't pass that
        # directly to qemu, but indirectly via virtiofsd.
        if config.output_format != OutputFormat.directory:
            os.chown(fname, INVOKING_USER.uid, INVOKING_USER.gid)

        if config.output_format == OutputFormat.disk and config.runtime_size:
            run(["systemd-repart",
                 "--definitions", "",
                 "--no-pager",
                 f"--size={config.runtime_size}",
                 "--pretty=no",
                 "--offline=yes",
                 fname])

        root = None
        if kernel:
            cmdline += ["-kernel", kernel]

            if config.output_format == OutputFormat.disk:
                # We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
                # kernel argument instead.
                root = finalize_root(find_partitions(fname))
                if not root:
                    die("Cannot perform a direct kernel boot without a root or usr partition")
            elif config.output_format == OutputFormat.directory:
                sock = stack.enter_context(start_virtiofsd(fname, uidmap=False))
                cmdline += [
                    "-chardev", f"socket,id={sock.name},path={sock}",
                    "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag=root",
                ]
                root = "root=root rootfstype=virtiofs rw"

        if kernel and (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios()):
            kcl = config.kernel_command_line + config.kernel_command_line_extra
        else:
            kcl = config.kernel_command_line_extra

        if root:
            kcl += [root]

        for src, target in config.runtime_trees:
            sock = stack.enter_context(start_virtiofsd(src, uidmap=True))
            cmdline += [
                "-chardev", f"socket,id={sock.name},path={sock}",
                "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag={sock.name}",
            ]
            kcl += [f"systemd.mount-extra={sock.name}:{target or f'/root/src/{src.name}'}:virtiofs"]

        if kernel and (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios()):
            cmdline += ["-append", " ".join(kcl)]
        elif config.architecture.supports_smbios():
            cmdline += [
                "-smbios",
                f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(kcl)}"
            ]

        if config.output_format == OutputFormat.cpio:
            cmdline += ["-initrd", fname]
        elif (
            kernel and KernelType.identify(kernel) != KernelType.uki and
            "-initrd" not in args.cmdline and
            (config.output_dir_or_cwd() / config.output_split_initrd).exists()
        ):
            cmdline += ["-initrd", config.output_dir_or_cwd() / config.output_split_initrd]

        if config.output_format == OutputFormat.disk:
            cmdline += ["-drive", f"if=none,id=mkosi,file={fname},format=raw",
                        "-device", "virtio-scsi-pci,id=scsi",
                        "-device", f"scsi-{'cd' if config.qemu_cdrom else 'hd'},drive=mkosi,bootindex=1"]

        if (
            firmware == QemuFirmware.uefi and
            config.qemu_swtpm != ConfigFeature.disabled and
            shutil.which("swtpm") is not None
        ):
            sock = stack.enter_context(start_swtpm())
            cmdline += ["-chardev", f"socket,id=chrtpm,path={sock}",
                        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]

            if config.architecture == Architecture.x86_64:
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == Architecture.arm64:
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        if QemuDeviceNode.vhost_vsock in qemu_device_fds and config.architecture.supports_smbios():
            addr, notifications = stack.enter_context(vsock_notify_handler())
            cmdline += ["-smbios", f"type=11,value=io.systemd.credential:vmm.notify_socket={addr}"]

        cmdline += config.qemu_args
        cmdline += args.cmdline

        with spawn(
            cmdline,
            # On Debian/Ubuntu, only users in the kvm group can access /dev/kvm. The invoking user might be part of the
            # kvm group, but the user namespace fake root user will definitely not be. Thus, we have to run qemu as the
            # invoking user to make sure we can access /dev/kvm. Of course, if we were invoked as root, none of this
            # matters as the root user will always be able to access /dev/kvm.
            user=INVOKING_USER.uid if not INVOKING_USER.invoked_as_root else None,
            group=INVOKING_USER.gid if not INVOKING_USER.invoked_as_root else None,
            stdin=sys.stdin,
            stdout=sys.stdout,
            pass_fds=qemu_device_fds.values(),
            env=os.environ,
            log=False,
            foreground=True,
        ) as qemu:
            # We have to close these before we wait for qemu otherwise we'll deadlock as qemu will never exit.
            for fd in qemu_device_fds.values():
                os.close(fd)

            qemu.wait()

    if status := int(notifications.get("EXIT_STATUS", 0)):
        raise subprocess.CalledProcessError(status, cmdline)
