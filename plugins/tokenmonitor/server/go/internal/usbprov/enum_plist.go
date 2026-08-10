package usbprov

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

// This file is the OS-agnostic core of macOS enumeration: a small XML-plist
// decoder for `ioreg -a` output and the IORegistry walk over the decoded tree.
// It carries no build tag (and imports nothing macOS-specific) so it compiles
// and unit-tests on every host, including the Linux CI runner — only the
// exec("ioreg") call that feeds it lives in enum_darwin.go. Mirrors the JS
// enum.js parsePlist/enumerateFromPlist and Python enum.py _enumerate_from_plist.

// portsFromPlist walks the decoded IORegistry plist tree, inheriting the nearest
// ancestor's USB vid/pid/iSerial down to every node carrying an IOCalloutDevice,
// and emits one Port per callout (de-duplicated by path, first wins).
func portsFromPlist(root any) []Port {
	var ports []Port
	seen := map[string]bool{}

	var visit func(node any, vid, pid uint16, haveVID, havePID bool, serial string)
	visit = func(node any, vid, pid uint16, haveVID, havePID bool, serial string) {
		m, ok := node.(map[string]any)
		if !ok {
			return
		}
		if v, ok := plistUint16(m["idVendor"]); ok {
			vid, haveVID = v, true
		}
		if p, ok := plistUint16(m["idProduct"]); ok {
			pid, havePID = p, true
		}
		if s, ok := m["kUSBSerialNumberString"].(string); ok && s != "" {
			serial = s
		} else if s, ok := m["USB Serial Number"].(string); ok && s != "" {
			serial = s
		}
		if callout, ok := m["IOCalloutDevice"].(string); ok && callout != "" &&
			!seen[callout] && haveVID && havePID {
			seen[callout] = true
			ports = append(ports, Port{
				Path:       callout,
				VID:        vid,
				PID:        pid,
				Serial:     serial,
				SerialNorm: NormalizeSerial(serial),
			})
		}
		if kids, ok := m["IORegistryEntryChildren"].([]any); ok {
			for _, k := range kids {
				visit(k, vid, pid, haveVID, havePID, serial)
			}
		}
	}

	roots, ok := root.([]any)
	if !ok {
		roots = []any{root}
	}
	for _, r := range roots {
		visit(r, 0, 0, false, false, "")
	}
	return ports
}

// plistUint16 accepts a plist integer that fits in a USB VID/PID (0..0xFFFF).
func plistUint16(v any) (uint16, bool) {
	n, ok := v.(int64)
	if !ok || n < 0 || n > 0xFFFF {
		return 0, false
	}
	return uint16(n), true
}

// parsePlist decodes the XML plist `ioreg -a` emits into a generic tree
// (dict→map[string]any, array→[]any, integer→int64, real→float64,
// string/data/date→string, true/false→bool). It is deliberately small — enough
// for ioreg output — and relies on encoding/xml for entity unescaping. Unknown
// value elements are skipped rather than erroring, so a future ioreg field type
// cannot break enumeration.
func parsePlist(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "plist" {
			return plistNextValue(dec)
		}
	}
}

// plistNextValue reads tokens until the next value start-element and decodes it.
// Returns nil if a close tag is reached first (empty container / <plist/>).
func plistNextValue(dec *xml.Decoder) (any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return plistDecodeElement(dec, t)
		case xml.EndElement:
			return nil, nil
		}
	}
}

func plistDecodeElement(dec *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		return plistDecodeDict(dec)
	case "array":
		return plistDecodeArray(dec)
	case "string", "data", "date":
		return plistDecodeText(dec)
	case "integer":
		s, err := plistDecodeText(dec)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return int64(0), nil // tolerate an unparseable integer as 0
		}
		return n, nil
	case "real":
		s, err := plistDecodeText(dec)
		if err != nil {
			return nil, err
		}
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	case "true":
		return true, dec.Skip()
	case "false":
		return false, dec.Skip()
	default:
		return nil, dec.Skip() // unknown element: consume its subtree
	}
}

// plistDecodeText accumulates character data until the current element closes.
// The caller has already consumed the start element.
func plistDecodeText(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			if err := dec.Skip(); err != nil { // no nested elements expected
				return "", err
			}
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

func plistDecodeDict(dec *xml.Decoder) (any, error) {
	m := map[string]any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				if err := dec.Skip(); err != nil {
					return nil, err
				}
				continue
			}
			key, err := plistDecodeText(dec)
			if err != nil {
				return nil, err
			}
			val, err := plistNextValue(dec)
			if err != nil {
				return nil, err
			}
			m[key] = val
		case xml.EndElement:
			return m, nil
		}
	}
}

func plistDecodeArray(dec *xml.Decoder) (any, error) {
	var arr []any
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			v, err := plistDecodeElement(dec, t)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		case xml.EndElement:
			return arr, nil
		}
	}
}
