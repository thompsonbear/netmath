package snet

import (
	"fmt"
	"math"
	"net/netip"
)

// network stuct based on netip.Prefix to add custom methods
type Subnet struct {
	netip.Prefix
}

func NewSubnet(p netip.Prefix) *Subnet {
	return &Subnet{Prefix: p}
}

func Parse(addrStr string, maskStr string) (*Subnet, error){
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return &Subnet{}, fmt.Errorf("invalid host address")
	}

	//TODO: validate mask sequential
	mask, err := netip.ParseAddr(maskStr)
	if err != nil {
		return &Subnet{}, fmt.Errorf("invalid subnet mask")
	}

	maskBits, _ := addrToBits(mask)
	p := netip.PrefixFrom(addr, maskBits)

	return &Subnet{Prefix: p}, nil
}

func ParseCIDR(s string) (*Subnet, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return &Subnet{}, fmt.Errorf("invalid ip prefix")
	}
	return &Subnet{Prefix: p}, nil
}

// network mask of the network
func (s Subnet) Mask() (netip.Addr, error) {
	addr := s.Addr()
	bits := s.Bits()

	mask, err := bitsToMask(bits, addr.Is4())
	if err != nil {
		return netip.IPv4Unspecified(), fmt.Errorf("invalid network mask")
	}

	return mask, nil
}

// network address of the network ex. 192.168.20.15/23 -> 192.168.20.0
func (s Subnet) Network() (netip.Addr, error) {
	addr := s.Addr()
	mask, err := s.Mask()
	if err != nil {
		return netip.IPv4Unspecified(), err
	}
	
	naBytes := getNetworkAddrBytes(addr.AsSlice(), mask.AsSlice())

	na, ok := netip.AddrFromSlice(naBytes)
	if !ok {
		return netip.IPv4Unspecified(), fmt.Errorf("invalid network address")
	}

	return na, nil
}

// broadcast address of the network ex. 192.168.20.15/23 -> 192.168.21.255
func (s Subnet) Broadcast() (netip.Addr, error) {
	addr := s.Addr()
	mask, err := s.Mask()
	if err != nil {
		return netip.IPv4Unspecified(), err
	}
	
	baBytes := getBroadcastAddrBytes(addr.AsSlice(), mask.AsSlice())

	ba, ok := netip.AddrFromSlice(baBytes)
	if !ok {
		return netip.IPv4Unspecified(), fmt.Errorf("invalid network address")
	}

	return ba, nil
}

//TODO: Support extra extra large IPv6 counts
func (s Subnet) Count() (int, error) {
	addr := s.Addr()
	bits := s.Bits()

	if (bits < 0 || bits > 128) {
		return 0, fmt.Errorf("invalid bit length")
	}

	var hostBits int
	if(addr.Is4()) {
		hostBits = 32 - bits
	} else if (addr.Is6()) {
		hostBits = 128 - bits
	} else {
		return 0, fmt.Errorf("invalid address")
	}

	hosts := math.Pow(2, float64(hostBits))

	return int(hosts), nil
}


func (s Subnet) All() ([]Subnet){
	addr := s.Addr()
	addrBytes := addr.AsSlice()
	
	mask, _ := s.Mask()
	maskBytes := mask.AsSlice()
	
	var netBytes []byte
	var step int

	for i := 0; i < len(maskBytes); i++ {
		if(maskBytes[i] < 255){
			step = 256 - int(maskBytes[i])
			break
		} else {
			netBytes = append(netBytes, addrBytes[i])
		}
	}

	var subnets []Subnet
	for j := 0; j < 255; j += step {
		tempBytes := netBytes
		tempBytes = append(tempBytes, byte(j))

		tempBytes = fillEmptyBytes(tempBytes, addr.Is4())
		tempAddr, _ := netip.AddrFromSlice(tempBytes)
		
		subnets = append(subnets, *NewSubnet(netip.PrefixFrom(tempAddr, s.Bits())))
	}

	return subnets
}

