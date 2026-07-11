// Package textutil holds tiny string helpers shared across the broker.
package textutil

// ClipRunes truncates s to at most n Unicode code points. The wire contract
// for 15-char fields (pet_name, quota-group labels) counts CODE POINTS —
// matching the Python implementation's s[:15] — so byte-based s[:n] (which
// can split a multi-byte UTF-8 sequence and emit invalid UTF-8 on the wire)
// must not be used for device-visible strings.
func ClipRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}
