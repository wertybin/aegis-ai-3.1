import os
import serial


class SerialBeacon:
    def __init__(self, port: str | None = None, baudrate: int = 115200):
        self.port = port or os.getenv("AEGIS_SERIAL_PORT", "")
        self.baudrate = baudrate

    def send_state(self, state: str) -> str:
        """Sends SAFE, SCANNING, or CRITICAL to an attached microcontroller if configured."""
        allowed = {"SAFE", "SCANNING", "CRITICAL"}
        clean_state = state.strip().upper()
        if clean_state not in allowed:
            return "INVALID_STATE"
        if not self.port:
            return f"BEACON_SKIPPED ({clean_state})"
        try:
            with serial.Serial(self.port, self.baudrate, timeout=1) as ser:
                ser.write(f"{clean_state}\n".encode("utf-8"))
            return f"BEACON_SENT ({clean_state} -> {self.port})"
        except Exception as exc:
            return f"BEACON_OFFLINE ({exc})"
