package snet

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

	if(bits <= 32 && is4) {
		mask := net.CIDRMask(bits, 32)
		ip = net.IP(mask).To4()
	} else {
		mask := net.CIDRMask(bits, 128)
		ip = net.IP(mask).To16()
	}
	addr, _ = netip.ParseAddr(ip.String())
	return addr, nil
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
	if(ipv4){
		size = 4
	} else {
		size = 16
	}

	for i := len(b); i < size; i++ {
		b = append(b, byte(0))
	}
	
	return b
}

func addrToBits(addr netip.Addr) (int, error) {
	addrBytes := addr.AsSlice()

    bits := 0
    for _, b := range addrBytes {
        // Count the number of set bits in each byte
        for mask := byte(0x80); mask != 0; mask >>= 1 {
            if b&mask != 0 {
                bits++
            }
        }
    }

    return bits, nil
}