// Tiny ring buffer of log lines.

export class Buffer {
  constructor(max = 200) {
    this.max = max > 0 ? max : 200;
    this.lines = [];
    this.partial = "";
  }
  writeLine(line) {
    this.lines.push(line);
    if (this.lines.length > this.max) this.lines = this.lines.slice(-this.max);
  }
  writeStream(chunk) {
    this.partial += chunk;
    let idx;
    while ((idx = this.partial.indexOf("\n")) !== -1) {
      const line = this.partial.slice(0, idx);
      this.partial = this.partial.slice(idx + 1);
      this.lines.push(line);
      if (this.lines.length > this.max) this.lines = this.lines.slice(-this.max);
    }
  }
  tail(n) {
    if (n <= 0 || n >= this.lines.length) return [...this.lines];
    return this.lines.slice(-n);
  }
  get length() { return this.lines.length; }
}
