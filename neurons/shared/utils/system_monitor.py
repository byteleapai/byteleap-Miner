"""
System Monitor
Cross-platform hardware and runtime information collection used by miner/worker
"""

import json
import os
import platform
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

import bittensor as bt
import psutil
import requests

try:
    import py3nvml.py3nvml as nvml

    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False

try:
    import cpuinfo

    CPUINFO_AVAILABLE = True
except ImportError:
    CPUINFO_AVAILABLE = False


class EnhancedSystemMonitor:
    """Enhanced system monitoring tool with improved cross-platform hardware detection"""

    def __init__(self):
        if NVML_AVAILABLE:
            try:
                nvml.nvmlInit()
                self._nvml_initialized = True
            except Exception:
                self._nvml_initialized = False
        else:
            self._nvml_initialized = False

    def get_system_info(self) -> Dict[str, Any]:
        return {
            "cpu_count": self.get_cpu_count(),
            "cpu_usage": self.get_cpu_usage(),
            "memory_total": self.get_memory_total(),
            "memory_available": self.get_memory_available(),
            "memory_usage": self.get_memory_usage(),
            "disk_total": self.get_disk_total(),
            "disk_free": self.get_disk_free(),
            "gpu_info": self.get_gpu_info(),
            "cpu_info": self.get_cpu_info(),
            "memory_info": self.get_memory_info(),
            "system_info": self.get_system_platform_info(),
            "motherboard_info": self.get_motherboard_info(),
            "uptime_seconds": self.get_system_uptime(),
            "public_ip": self.get_public_ip(),
            "storage_info": self.get_storage_info(),
        }

    def get_cpu_count(self) -> int:
        return psutil.cpu_count(logical=True)

    def get_cpu_usage(self) -> float:
        return psutil.cpu_percent(interval=None)

    def get_memory_total(self) -> int:
        return psutil.virtual_memory().total // (1024 * 1024)

    def get_memory_available(self) -> int:
        return psutil.virtual_memory().available // (1024 * 1024)

    def get_memory_usage(self) -> float:
        return psutil.virtual_memory().percent

    def get_disk_total(self) -> int:
        return psutil.disk_usage("/").total // (1024 * 1024 * 1024)

    def get_disk_free(self) -> int:
        return psutil.disk_usage("/").free // (1024 * 1024 * 1024)

    def get_storage_info(self) -> Dict[str, Any]:
        """Collect per-device storage information (Linux only).

        Returns: { 'storage': [ { device, type, model, serial, bus, total_gb, free_gb, filesystem: [...], notes } ] }
        On non-Linux systems, returns { 'storage': [] } for simplicity.
        """
        try:
            if platform.system() == "Linux":
                return {"storage": self._get_storage_info_linux()}
        except Exception as e:
            bt.logging.debug(f"Storage info collection error: {e}")
        return {"storage": []}

    def _get_storage_info_linux(self) -> List[Dict[str, Any]]:
        storage: List[Dict[str, Any]] = []

        lsblk_path = shutil.which("lsblk")
        lsblk_json: Optional[Dict[str, Any]] = None
        if lsblk_path:
            try:
                result = subprocess.run(
                    [
                        lsblk_path,
                        "-J",
                        "-b",
                        "-o",
                        "NAME,PATH,TYPE,SIZE,ROTA,MODEL,SERIAL,TRAN,FSTYPE,MOUNTPOINT",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    lsblk_json = json.loads(result.stdout)
            except Exception as e:
                bt.logging.debug(f"lsblk parse error: {e}")

        # Prepare mount usage cache
        mount_usage: Dict[str, Tuple[int, int]] = {}
        try:
            for p in psutil.disk_partitions(all=True):
                try:
                    u = psutil.disk_usage(p.mountpoint)
                    mount_usage[p.mountpoint] = (
                        int(u.total // (1024**3)),
                        int(u.free // (1024**3)),
                    )
                except Exception:
                    continue
        except Exception:
            pass

        def build_dev_entry(dev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            try:
                dev_type = (dev.get("type") or "").lower()
                path = dev.get("path") or dev.get("name")
                if not path:
                    return None
                # Only include real block devices
                if dev_type not in {"disk", "nvme", "rom"}:
                    return None
                size_b = int(dev.get("size") or 0)
                rota = int(dev.get("rota") or 0)
                model = dev.get("model") or None
                serial = dev.get("serial") or None
                tran = (dev.get("tran") or "").lower() or None

                # Device classification
                d_type = (
                    "nvme"
                    if tran == "nvme" or dev_type == "nvme"
                    else ("ssd" if rota == 0 else "hdd")
                )
                if dev_type in {"rom"}:
                    d_type = "virtual"

                filesystems: List[Dict[str, Any]] = []
                mounts_seen: set = set()

                # Gather mounts from children recursively
                def walk_children(node: Dict[str, Any]):
                    for ch in node.get("children", []) or []:
                        mnt = ch.get("mountpoint") or ch.get("mountpoint")  # same key
                        fs = ch.get("fstype") or None
                        if mnt and mnt not in mounts_seen:
                            mounts_seen.add(mnt)
                            size_free = mount_usage.get(mnt)
                            if size_free:
                                filesystems.append(
                                    {
                                        "mount": mnt,
                                        "fs": fs,
                                        "size_gb": size_free[0],
                                        "free_gb": size_free[1],
                                    }
                                )
                        # Recurse deeper
                        if ch.get("children"):
                            walk_children(ch)

                walk_children(dev)

                # free_gb is sum across mounted filesystems on this device
                free_gb = int(sum(fs.get("free_gb", 0) for fs in filesystems))

                entry = {
                    "device": path,
                    "type": d_type,
                    "model": model,
                    "serial": serial,
                    "bus": tran,
                    "total_gb": int(size_b // (1024**3)),
                    "free_gb": free_gb,
                    "filesystem": filesystems,
                    "notes": {"rotational": bool(rota), "lsblk_type": dev_type},
                }
                return entry
            except Exception:
                return None

        if lsblk_json and isinstance(lsblk_json.get("blockdevices"), list):
            for dev in lsblk_json["blockdevices"]:
                entry = build_dev_entry(dev)
                if entry:
                    storage.append(entry)

        # Fallback if lsblk missing or returned nothing: group by base device from partitions
        if not storage:
            try:
                parts = psutil.disk_partitions(all=False)
                groups: Dict[str, Dict[str, Any]] = {}
                for p in parts:
                    dev_path = p.device or p.mountpoint
                    base = self._linux_base_device(dev_path)
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        size_gb = int(u.total // (1024**3))
                        free_gb = int(u.free // (1024**3))
                    except Exception:
                        size_gb = 0
                        free_gb = 0
                    grp = groups.setdefault(
                        base,
                        {
                            "device": base,
                            "type": "unknown",
                            "model": None,
                            "serial": None,
                            "bus": None,
                            "total_gb": 0,
                            "free_gb": 0,
                            "filesystem": [],
                            "notes": {"source": "fallback_grouped_partitions"},
                        },
                    )
                    grp["filesystem"].append(
                        {
                            "mount": p.mountpoint,
                            "fs": p.fstype or None,
                            "size_gb": size_gb,
                            "free_gb": free_gb,
                        }
                    )
                    grp["free_gb"] += free_gb
                # Try to read actual device size from /sys if available
                for base, grp in groups.items():
                    size_b = self._linux_get_device_size_bytes(base)
                    if size_b:
                        grp["total_gb"] = int(size_b // (1024**3))
                    else:
                        # Approximate by sum of filesystem sizes
                        grp["total_gb"] = int(
                            sum(fs.get("size_gb", 0) for fs in grp["filesystem"])
                        )
                    storage.append(grp)
            except Exception:
                pass

        return storage

    def _linux_base_device(self, dev_path: str) -> str:
        """Get the base block device path for a partition path.
        Examples:
            /dev/nvme0n1p2 -> /dev/nvme0n1
            /dev/sda1 -> /dev/sda
        """
        try:
            name = os.path.basename(dev_path or "")
            if name.startswith("nvme"):
                m = re.match(r"^(nvme\d+n\d+)", name)
                if m:
                    return f"/dev/{m.group(1)}"
            m = re.match(r"^([a-zA-Z]+)\d+", name)
            if m:
                return f"/dev/{m.group(1)}"
        except Exception:
            pass
        return dev_path

    def _linux_get_device_size_bytes(self, base_path: str) -> Optional[int]:
        try:
            base = os.path.basename(base_path)
            # Handle /dev/mapper/... which aren't in /sys/block
            if base.startswith("mapper/"):
                return None
            sys_size = f"/sys/class/block/{base}/size"
            if os.path.exists(sys_size):
                with open(sys_size, "r") as f:
                    sectors = int(f.read().strip() or 0)
                    return sectors * 512
        except Exception:
            pass
        return None

    def get_gpu_info(self) -> List[Dict[str, Any]]:
        """Return GPU info preferring NVML (no GPUtil dependency)."""
        try:
            return self.get_gpu_info_nvml()
        except Exception:
            return []

    def get_gpu_info_nvml(self) -> List[Dict[str, Any]]:
        """Return GPU info via NVML, including UUIDs. Returns empty list if NVML not initialized."""
        if not self._nvml_initialized:
            return []
        result: List[Dict[str, Any]] = []
        try:
            device_count = nvml.nvmlDeviceGetCount()
            for i in range(device_count):
                handle = nvml.nvmlDeviceGetHandleByIndex(i)
                name = nvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8")
                memory_info = nvml.nvmlDeviceGetMemoryInfo(handle)
                util_rates = nvml.nvmlDeviceGetUtilizationRates(handle)
                temp = nvml.nvmlDeviceGetTemperature(handle, nvml.NVML_TEMPERATURE_GPU)
                try:
                    uuid_val = nvml.nvmlDeviceGetUUID(handle)
                    if isinstance(uuid_val, bytes):
                        uuid_val = uuid_val.decode("utf-8")
                except Exception:
                    uuid_val = None
                result.append(
                    {
                        "id": i,
                        "name": name,
                        "memory_total": memory_info.total // (1024 * 1024),
                        "memory_used": memory_info.used // (1024 * 1024),
                        "memory_free": memory_info.free // (1024 * 1024),
                        "memory_util": (memory_info.used / memory_info.total) * 100,
                        "gpu_util": getattr(util_rates, "gpu", None),
                        "temperature": temp,
                        "vendor": "NVIDIA",
                        "type": "discrete",
                        "uuid": uuid_val,
                    }
                )
        except Exception:
            return []
        return result

    def get_cpu_info(self) -> Dict[str, Any]:
        try:
            cpu_info: Dict[str, Any] = {}
            cpu_info["logical_cores"] = psutil.cpu_count(logical=True)
            cpu_info["physical_cores"] = psutil.cpu_count(logical=False)
            cpu_info["architecture"] = platform.machine()
            cpu_info["processor"] = platform.processor()
            try:
                freq = psutil.cpu_freq()
                if freq:
                    cpu_info["frequency_mhz"] = {
                        "current": freq.current,
                        "min": freq.min,
                        "max": freq.max,
                    }
            except Exception:
                pass
            if platform.system() == "Darwin":
                try:
                    result = subprocess.run(
                        ["system_profiler", "SPHardwareDataType", "-json"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        import json

                        data = json.loads(result.stdout)
                        hardware = data.get("SPHardwareDataType", [{}])[0]
                        chip_type = hardware.get("chip_type")
                        machine_model = hardware.get("machine_model")
                        machine_name = hardware.get("machine_name")
                        if chip_type:
                            cpu_info["brand"] = chip_type
                            cpu_info["model"] = chip_type
                            cpu_info["vendor_id"] = "Apple"
                        if machine_model:
                            cpu_info["machine_model"] = machine_model
                        if machine_name:
                            cpu_info["machine_name"] = machine_name
                        if chip_type:
                            if "M1" in chip_type:
                                cpu_info["family"] = "Apple Silicon M1"
                            elif "M2" in chip_type:
                                cpu_info["family"] = "Apple Silicon M2"
                            elif "M3" in chip_type:
                                cpu_info["family"] = "Apple Silicon M3"
                            elif "M4" in chip_type:
                                cpu_info["family"] = "Apple Silicon M4"
                            else:
                                cpu_info["family"] = "Apple Silicon"
                        processor_info = hardware.get("number_processors", "")
                        if processor_info and "proc" in processor_info:
                            parts = processor_info.replace("proc ", "").split(":")
                            if len(parts) >= 3:
                                cpu_info["total_cores"] = int(parts[0])
                                cpu_info["performance_cores"] = int(parts[1])
                                cpu_info["efficiency_cores"] = int(parts[2])
                        bt.logging.debug(f"macOS CPU detected: {chip_type}")
                except Exception as e:
                    bt.logging.debug(f"Could not get macOS CPU info: {e}")
            elif platform.system() == "Linux":
                try:
                    with open("/proc/cpuinfo", "r") as f:
                        cpuinfo_content = f.read()
                        for line in cpuinfo_content.split("\n"):
                            if "model name" in line:
                                cpu_info["model_name"] = line.split(":")[1].strip()
                                if (
                                    not cpu_info.get("brand")
                                    or cpu_info.get("brand") == "Unknown"
                                ):
                                    cpu_info["brand"] = cpu_info["model_name"]
                                break
                except Exception:
                    pass
            if CPUINFO_AVAILABLE:
                try:
                    detailed_info = cpuinfo.get_cpu_info()
                    if not cpu_info.get("brand") or cpu_info.get("brand") == "Unknown":
                        cpu_info["brand"] = detailed_info.get(
                            "brand_raw", detailed_info.get("brand", "Unknown")
                        )
                    if not cpu_info.get("model") or cpu_info.get("model") == "Unknown":
                        cpu_info["model"] = detailed_info.get("model", "Unknown")
                    if (
                        not cpu_info.get("family")
                        or cpu_info.get("family") == "Unknown"
                    ):
                        cpu_info["family"] = detailed_info.get("family", "Unknown")
                except Exception:
                    pass
            return cpu_info
        except Exception as e:
            bt.logging.warning(f"Error getting CPU info: {e}")
            return {"error": str(e)}

    def get_memory_info(self) -> Dict[str, Any]:
        try:
            vm = psutil.virtual_memory()
            sm = psutil.swap_memory()
            return {
                "total": vm.total // (1024 * 1024),
                "available": vm.available // (1024 * 1024),
                "used": vm.used // (1024 * 1024),
                "percent": vm.percent,
                "swap_total": sm.total // (1024 * 1024),
                "swap_used": sm.used // (1024 * 1024),
                "swap_percent": sm.percent,
            }
        except Exception as e:
            bt.logging.warning(f"Error getting memory info: {e}")
            return {"error": str(e)}

    def get_system_platform_info(self) -> Dict[str, Any]:
        try:
            return {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            }
        except Exception as e:
            bt.logging.warning(f"Error getting system info: {e}")
            return {"error": str(e)}

    def get_motherboard_info(self) -> Dict[str, Any]:
        try:
            mb_info: Dict[str, Any] = {}
            if platform.system() == "Linux":
                try:
                    result = subprocess.run(
                        ["dmidecode", "-s", "baseboard-manufacturer"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        mb_info["manufacturer"] = result.stdout.strip()
                    result = subprocess.run(
                        ["dmidecode", "-s", "baseboard-product-name"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        mb_info["product_name"] = result.stdout.strip()
                    result = subprocess.run(
                        ["dmidecode", "-s", "system-serial-number"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        serial = result.stdout.strip()
                        if serial and serial != "To Be Filled By O.E.M.":
                            mb_info["serial_number"] = serial
                except Exception as e:
                    bt.logging.debug(f"Could not get DMI info: {e}")
            elif platform.system() == "Darwin":
                try:
                    result = subprocess.run(
                        ["system_profiler", "SPHardwareDataType", "-json"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        import json

                        data = json.loads(result.stdout)
                        hardware = data.get("SPHardwareDataType", [{}])[0]
                        mb_info["brand"] = "Apple"
                        mb_info["model_identifier"] = hardware.get(
                            "machine_model", "Unknown"
                        )
                        mb_info["machine_name"] = hardware.get(
                            "machine_name", "Unknown"
                        )
                        mb_info["serial_number"] = hardware.get(
                            "serial_number", "Unknown"
                        )
                        mb_info["chip_type"] = hardware.get("chip_type", "Unknown")
                        physical_memory = hardware.get("physical_memory", "Unknown")
                        if physical_memory and physical_memory != "Unknown":
                            mb_info["physical_memory"] = physical_memory
                except Exception as e:
                    bt.logging.debug(f"Could not get macOS hardware info: {e}")
            elif platform.system() == "Windows":
                try:
                    result = subprocess.run(
                        [
                            "wmic",
                            "baseboard",
                            "get",
                            "manufacturer,product,serialnumber",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        lines = result.stdout.strip().split("\n")
                        if len(lines) > 1:
                            values = lines[1].split()
                            if len(values) >= 3:
                                mb_info["manufacturer"] = values[0]
                                mb_info["product_name"] = values[1]
                                mb_info["serial_number"] = values[2]
                except Exception as e:
                    bt.logging.debug(f"Could not get Windows motherboard info: {e}")
            return mb_info
        except Exception as e:
            bt.logging.warning(f"Error getting motherboard info: {e}")
            return {"error": str(e)}

    def get_system_uptime(self) -> Optional[float]:
        try:
            return time.time() - psutil.boot_time()
        except Exception as e:
            bt.logging.warning(f"Error getting system uptime: {e}")
            return None

    def get_public_ip(self) -> Optional[str]:
        try:
            response = requests.get("https://httpbin.org/ip", timeout=5)
            if response.status_code == 200:
                return response.json().get("origin")
        except Exception:
            pass
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            if response.status_code == 200:
                return response.json().get("ip")
        except Exception:
            pass
        return None
