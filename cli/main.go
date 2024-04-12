package main

import (
	"fmt"
	"net/netip"

	"github.com/thompsonbear/snet"
)

func main(){
	prefix,_ := netip.ParsePrefix("172.21.20.10/24")

	s := snet.New(prefix)

	fmt.Println(s.Mask())
}
