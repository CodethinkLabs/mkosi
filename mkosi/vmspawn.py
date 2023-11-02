import contextlib
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import (
    ConfigFeature,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
)
from mkosi.log import die
from mkosi.partition import finalize_root, find_partitions
from mkosi.run import run, spawn
from mkosi.types import PathString
from mkosi.util import INVOKING_USER
from mkosi.qemu import (
    QemuDeviceNode,
    KernelType,
    vsock_notify_handler,
    start_swtpm,
    start_virtiofsd,
    machine_cid,
    copy_ephemeral
)


def config_feature_to_tristate(cf: ConfigFeature) -> str:
    if cf == ConfigFeature.enabled:
        return "yes"
    if cf == ConfigFeature.disabled:
        return "no"
    return ""


def run_vmspawn(args: MkosiArgs, config: MkosiConfig, qemu_device_fds: Mapping[QemuDeviceNode, int]) -> None:
    if config.output_format != OutputFormat.disk:
        die(f"{config.output_format} images cannot be booted in systemd-vmspawn")

    if (config.runtime_trees and config.qemu_firmware == QemuFirmware.bios):
        die("RuntimeTrees= cannot be used when booting in BIOS firmware")

    if config.qemu_kvm == ConfigFeature.enabled and not QemuDeviceNode.kvm.available():
        die("KVM acceleration requested but cannot access /dev/kvm")

    if config.qemu_vsock == ConfigFeature.enabled and QemuDeviceNode.vhost_vsock not in qemu_device_fds:
        die("VSock requested but cannot access /dev/vhost-vsock")

    if config.qemu_cdrom:
        die("systemd-vmspawn does not support CD-ROM images")

    if config.qemu_kernel:
        kernel = config.qemu_kernel
    elif "-kernel" in args.cmdline:
        kernel = Path(args.cmdline[args.cmdline.index("-kernel") + 1])
    else:
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

    if firmware == QemuFirmware.linux:
        kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}, please install a kernel in the image "
                "or provide a -kernel argument to mkosi vmspawn"
            )

    notifications: dict[str, str] = {}
    cmdline: list[PathString] = [
        "systemd-vmspawn",
        f"--qemu-smp={config.qemu_smp}",
        f"--qemu-mem={config.qemu_mem}",
        f"--qemu-kvm={config_feature_to_tristate(config.qemu_kvm)}",

        # we need to handle this ourselves as we cannot pass the fd to vmspawn
        # directly but have to pass it to qemu instead
        # to prevent a conflict we disable vsock for vmspawn
        "--qemu-vsock=no",
    ]

    if config.qemu_gui:
        cmdline.append("--qemu-gui")

    if config.secure_boot:
        cmdline.append("--secure-boot=yes")

    for name, val in config.credentials.items():
        cmdline.append(f"--set-credential={name}:{val}")

    # values which we need to pass directly to qemu
    qemu_cmdline: list[PathString] = []

    if QemuDeviceNode.vhost_vsock in qemu_device_fds:
        qemu_cmdline += [
            "-device",
            f"vhost-vsock-pci,guest-cid={machine_cid(config)},vhostfd={qemu_device_fds[QemuDeviceNode.vhost_vsock]}"
        ]

    with contextlib.ExitStack() as stack:
        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = config.output_dir_or_cwd() / config.output

        # Make sure qemu can access the ephemeral copy. Not required for directory output because we don't pass that
        # directly to qemu, but indirectly via virtiofsd.
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
            qemu_cmdline += ["-kernel", kernel]

            # We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
            # kernel argument instead.
            root = finalize_root(find_partitions(fname))
            if not root:
                die("Cannot perform a direct kernel boot without a root or usr partition")

        cmdline += [f"--image={fname}"]

        if kernel and (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios()):
            kcl = config.kernel_command_line + config.kernel_command_line_extra
        else:
            kcl = config.kernel_command_line_extra

        if root:
            kcl += [root]

        for src, target in config.runtime_trees:
            sock = stack.enter_context(start_virtiofsd(src, uidmap=True))
            qemu_cmdline += [
                "-chardev", f"socket,id={sock.name},path={sock}",
                "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag={sock.name}",
            ]
            kcl += [f"systemd.mount-extra={sock.name}:{target or f'/root/src/{src.name}'}:virtiofs"]

        if kernel and (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios()):
            qemu_cmdline += ["-append", " ".join(kcl)]
        elif config.architecture.supports_smbios():
            qemu_cmdline += [
                "-smbios",
                f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(kcl)}"
            ]

        if (
            kernel and KernelType.identify(kernel) != KernelType.uki and
            "-initrd" not in args.cmdline and
            (config.output_dir_or_cwd() / config.output_split_initrd).exists()
        ):
            qemu_cmdline += ["-initrd", config.output_dir_or_cwd() / config.output_split_initrd]


        if (
            firmware == QemuFirmware.uefi and
            config.qemu_swtpm != ConfigFeature.disabled and
            shutil.which("swtpm") is not None
        ):
            sock = stack.enter_context(start_swtpm())
            qemu_cmdline += ["-chardev", f"socket,id=chrtpm,path={sock}",
                        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]

            if config.architecture == Architecture.x86_64:
                qemu_cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == Architecture.arm64:
                qemu_cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        if QemuDeviceNode.vhost_vsock in qemu_device_fds and config.architecture.supports_smbios():
            addr, notifications = stack.enter_context(vsock_notify_handler())
            qemu_cmdline += ["-smbios", f"type=11,value=io.systemd.credential:vmm.notify_socket={addr}"]

        cmdline += ["--"]
        cmdline += config.qemu_args
        cmdline += args.cmdline
        cmdline += qemu_cmdline

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
