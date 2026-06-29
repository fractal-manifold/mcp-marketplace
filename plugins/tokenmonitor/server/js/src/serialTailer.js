// USB-CDC serial tailer. Optional: loaded lazily so a missing serialport
// dependency only affects the firmware-logs path, not the broker.

export class Tailer {
  constructor(device, buf, { baud = 115200 } = {}) {
    this.device = device;
    this.buf = buf;
    this.baud = baud;
    this._connected = false;
    this._aborted = false;
    this._port = null;
  }
  connected() { return this._connected; }
  async start() {
    if (!this.device) return;
    let SerialPort;
    try { ({ SerialPort } = await import("serialport")); }
    catch (e) { return; /* tailing disabled */ }
    const open = () => new Promise((resolve) => {
      try {
        this._port = new SerialPort({ path: this.device, baudRate: this.baud }, (err) => {
          if (err) return resolve(false);
          this._connected = true;
          let pending = "";
          this._port.on("data", (chunk) => {
            pending += chunk.toString("utf8");
            let i;
            while ((i = pending.indexOf("\n")) !== -1) {
              this.buf.writeLine(pending.slice(0, i).replace(/\r$/, ""));
              pending = pending.slice(i + 1);
            }
          });
          this._port.on("close", () => { this._connected = false; resolve(true); });
          this._port.on("error", () => { this._connected = false; });
        });
      } catch { resolve(false); }
    });
    while (!this._aborted) {
      await open();
      this._connected = false;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  stop() { this._aborted = true; if (this._port) try { this._port.close(); } catch {} }
}
