// Tiny string helpers shared across the broker.

// clipCodePoints truncates s to at most n Unicode CODE POINTS. The wire
// contract for 15-char fields (pet_name, quota-group labels) counts code
// points — matching Python's s[:15] and Go's textutil.ClipRunes — so
// String.prototype.slice (which counts UTF-16 units and can split an astral
// pair, emitting a lone surrogate on the wire) must not be used for
// device-visible strings.
export function clipCodePoints(s, n) {
  s = String(s);
  if (n <= 0) return "";
  let count = 0;
  let idx = 0; // UTF-16 unit index of the cut point
  for (const cp of s) {
    if (count === n) return s.slice(0, idx);
    idx += cp.length; // 1 for BMP, 2 for an astral surrogate pair
    count += 1;
  }
  return s;
}
