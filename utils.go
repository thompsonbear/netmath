package netmath

import (
	"fmt"
	"net"
	"net/netip"
)

func bitsToMask(bits int, is4 bool) (netip.Addr, error) {
	if bits < 0 || bits > 128 {
		return netip.IPv4Unspecified(), fmt.Errorf("invalid bit length")
	}

	var ip net.IP
	var addr netip.Addr
	//TODO: Handle this internally?
	if bits <= 32 && is4 {
		mask := net.CIDRMask(bits, 32)
		ip = net.IP(mask).To4()
	} else {
		mask := net.CIDRMask(bits, 128)
		ip = net.IP(mask).To16()
	}
	addr, _ = netip.ParseAddr(ip.String())
	return addr, nil
}

func maskToBits(mask netip.Addr) (int, error) {
	maskBytes := mask.AsSlice()

	bits := 0
	ended := false
	for _, b := range maskBytes {
		// Count the number of set bits in each byte
		for m := byte(0x80); m != 0; m >>= 1 {
			if b&m != 0 && ended {
				return 0, fmt.Errorf("invalid subnet mask")
			} else if b&m != 0 {
				bits++
			} else {
				ended = true
			}
		}
	}

	return bits, nil
}

func getNetworkAddrBytes(ipBytes []byte, maskBytes []byte) []byte {
	naBytes := make([]byte, len(ipBytes))
	for i := range ipBytes {
		// Bitwise AND
		naBytes[i] = ipBytes[i] & maskBytes[i]
	}
	return naBytes
}

func getBroadcastAddrBytes(ipBytes []byte, maskBytes []byte) []byte {
	baBytes := make([]byte, len(ipBytes))
	for i := range ipBytes {
		// Bitwise OR
		baBytes[i] = ipBytes[i] | ^maskBytes[i]
	}
	return baBytes
}

func fillEmptyBytes(b []byte, ipv4 bool) []byte {
	if len(b) > 16 {
		return b
	}

	var size int
	if ipv4 {
		size = 4
	} else {
		size = 16
	}

	for i := len(b); i < size; i++ {
		b = append(b, byte(0))
	}

	return b
}
