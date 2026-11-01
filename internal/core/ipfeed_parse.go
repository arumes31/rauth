package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const MaxIPFeeds = 32
const MaxFeedBytes = 10 << 20
const MaxFeedPrefixes = 500000
const MaxWorkerFeedPrefixes = 2000000

// compiledIPFeed is immutable after construction. Prefix lengths are indexed
// separately so matching does not scan the complete downloaded list.
type compiledIPFeed struct {
	prefixes map[int]map[netip.Addr]struct{}
	lengths  []int
	count    int
}

func parseFeed(body []byte, allowEmpty bool) (*compiledIPFeed, []byte, error) {
	if len(body) > MaxFeedBytes {
		return nil, nil, errors.New("feed exceeds download size limit")
	}
	index := &compiledIPFeed{prefixes: map[int]map[netip.Addr]struct{}{}}
	canonical := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 4096)
	line := 0
	for scanner.Scan() {
		line++
		value := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if before, _, ok := strings.Cut(value, "#"); ok {
			value = strings.TrimSpace(before)
		}
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, e := netip.ParseAddr(value)
			if e != nil || address.Zone() != "" {
				return nil, nil, fmt.Errorf("invalid IP or CIDR on line %d", line)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		address := prefix.Addr()
		if address.Zone() != "" {
			return nil, nil, fmt.Errorf("scoped IP on line %d", line)
		}
		if address.Is4In6() {
			if prefix.Bits() < 96 {
				return nil, nil, fmt.Errorf("ambiguous mapped IPv4 prefix on line %d", line)
			}
			prefix = netip.PrefixFrom(address.Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if _, exists := canonical[prefix.String()]; exists {
			continue
		}
		canonical[prefix.String()] = struct{}{}
		if len(canonical) > MaxFeedPrefixes {
			return nil, nil, errors.New("feed exceeds prefix limit")
		}
		bits := prefix.Bits()
		if index.prefixes[bits] == nil {
			index.prefixes[bits] = map[netip.Addr]struct{}{}
			index.lengths = append(index.lengths, bits)
		}
		index.prefixes[bits][prefix.Addr()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, errors.New("feed contains an oversized or unreadable line")
	}
	if len(canonical) == 0 && !allowEmpty {
		return nil, nil, errors.New("empty feed requires explicit acceptance")
	}
	index.count = len(canonical)
	sort.Sort(sort.Reverse(sort.IntSlice(index.lengths)))
	values := make([]string, 0, len(canonical))
	for value := range canonical {
		values = append(values, value)
	}
	sort.Strings(values)
	normalized := []byte(strings.Join(values, "\n"))
	if len(normalized) > MaxFeedBytes {
		return nil, nil, errors.New("normalized feed exceeds size limit")
	}
	return index, normalized, nil
}
func (f *compiledIPFeed) contains(address netip.Addr) bool {
	address = address.Unmap()
	for _, bits := range f.lengths {
		if bits > address.BitLen() {
			continue
		}
		network := netip.PrefixFrom(address, bits).Masked().Addr()
		if _, ok := f.prefixes[bits][network]; ok {
			return true
		}
	}
	return false
}
