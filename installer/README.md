# CNServerOps SSD installer

This installer builds a new CNServerOps boot SSD from an immutable runtime
package and a clean Ubuntu/Debian root filesystem archive. It does not mount,
clone, or copy a live CNServerOps SSD.

## Prepare a bundle (Ubuntu/Debian)

On an Ubuntu 22.04/24.04 or Debian 12 builder, create a clean root filesystem
once (or use an approved offline archive).  The rootfs must include a kernel,
systemd, Python, generic DHCP/network tools, IPMI and the hardware-inventory
utilities used by CNServerOps; a `minbase` archive by itself is not bootable:

```sh
sudo apt-get update
sudo apt-get install -y debootstrap gdisk dosfstools e2fsprogs grub-efi-amd64-bin util-linux tar
sudo debootstrap --arch=amd64 --variant=minbase \
  --components=main,universe \
  --include=linux-image-amd64,systemd-sysv,systemd,udev,python3,openssh-server,\
iproute2,iputils-ping,netplan.io,ethtool,pciutils,dmidecode,smartmontools,\
nvme-cli,curl,ca-certificates,openssl,sudo,kmod,e2fsprogs,tar,gzip,less,locales,\
ipmitool \
  bookworm /var/tmp/cnserverops-rootfs http://deb.debian.org/debian
sudo tar --numeric-owner --xattrs --acls -C /var/tmp/cnserverops-rootfs -cf rootfs.tar .
```

For Ubuntu use `noble` (or `jammy`), the Ubuntu mirror, and the matching
kernel package (`linux-image-generic`).  If a distribution's debootstrap
stage does not expose `universe`, enable that component before running the
command or install `ipmitool` and the listed utilities in the rootfs before
archiving it.  The bundle builder accepts `.tar`, `.tar.gz`, `.tar.xz` and
`.tar.bz2` archives and records the rootfs hash in the immutable bundle.

Then build an offline installer bundle from the versioned runtime release:

```sh
python3 installer/build_ssd_installer_bundle.py \
  --runtime-package dist/cnserverops-runtime-<VERSION>.tar.gz \
  --rootfs-tar rootfs.tar \
  --output cnserverops-ssd-installer-<VERSION>.tar.gz
```

The builder verifies the runtime package SHA and immutable release manifest
before adding it to the bundle. The bundle records hashes for every member.

## Technician use

Extract the bundle on the Linux builder or technician workstation, connect a
blank SSD, and run:

```sh
sudo ./installer/cnserverops-ssd-setup.sh --check
sudo ./installer/cnserverops-ssd-setup.sh --dry-run
sudo ./installer/cnserverops-ssd-setup.sh
```

The installer lists every whole disk with path, model, serial, capacity,
partitions/mounts, and read-only state. It blocks the current system disk,
mounted/in-use disks, read-only disks, and disks containing the package or
rootfs. No disk is selected automatically. The destructive confirmation must
match `WIPE /dev/<device>` exactly.

Use `--target /dev/<device>` only when the displayed device identity has been
checked. `--dry-run` never calls `wipefs`, `sgdisk`, `mkfs`, `mount`, or
`grub-install`.

If the builder is missing required tools, install the packages listed above and
run `--check` again. Alternatively, on a Debian/Ubuntu builder you may request
the explicit bootstrap step once with `sudo ... --bootstrap-deps --apt-update`.
Dependency installation is intentionally explicit; the installer never runs
`apt` implicitly during a production disk build.

## What is installed

The target receives GPT, a 512 MiB EFI partition labelled `CN_ESP`, and an
ext4 root partition labelled `CNSERVEROPS_ROOT`. The immutable runtime is
installed below `/opt/cnserverops/releases/<VERSION>` and `/opt/cnserverops/current`
is a relative pointer. UEFI fallback files are written by `grub-install`.

The template uses generic DHCP and the existing CNServerOps console, clone
first-boot, firmware-resume, and sync-retry units. First boot generates a new
machine identity, SSH host keys, storage fingerprint, and RUNNER_ID. The
installer deliberately leaves no runner.json, run IDs, firmware checkpoints,
BMC operational secret, handoff marker, report, old machine-id, or development
static IP on the image.

## Validation and recovery

Installation writes `var/log/cnserverops/ssd-installer-final.json` and validates
the GPT filesystem labels, fstab UUIDs, UEFI files, immutable release hashes,
relative runtime/unit links, DHCP configuration, Central URL syntax, clean
mutable state, and first-boot marker. A failure exits non-zero and leaves the
source package untouched; do not reuse a target until it has been inspected or
reformatted.

The installer is safe to rerun on a newly selected blank target. It never
changes the builder's system disk and does not require Internet access after
the runtime package, rootfs archive, and host dependencies are available.
