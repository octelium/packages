package rpm

import (
	"strconv"
	"strings"
)

func CompareEVR(a, b string) int {
	ae, av, ar := splitEVR(a)
	be, bv, br := splitEVR(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := vercmp(av, bv); c != 0 {
		return c
	}
	return vercmp(ar, br)
}

func splitEVR(evr string) (epoch int, version, release string) {
	if e, rest, ok := strings.Cut(evr, ":"); ok {
		epoch, _ = strconv.Atoi(e)
		evr = rest
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		return epoch, evr[:i], evr[i+1:]
	}
	return epoch, evr, ""
}

func isAlnum(c byte) bool {
	return isDigit(c) || isAlpha(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func vercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		ai, bj := i < len(a), j < len(b)
		if (ai && a[i] == '~') || (bj && b[j] == '~') {
			if !ai || a[i] != '~' {
				return 1
			}
			if !bj || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (ai && a[i] == '^') || (bj && b[j] == '^') {
			if !ai {
				return -1
			}
			if !bj {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if !ai || !bj {
			break
		}

		si, sj := i, j
		numeric := isDigit(a[i])
		class := isAlpha
		if numeric {
			class = isDigit
		}
		for si < len(a) && class(a[si]) {
			si++
		}
		for sj < len(b) && class(b[sj]) {
			sj++
		}
		if sj == j {
			if numeric {
				return 1
			}
			return -1
		}
		sa, sb := a[i:si], b[j:sj]
		if numeric {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		i, j = si, sj
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}
