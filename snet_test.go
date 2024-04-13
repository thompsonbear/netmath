package snet

import (
	"testing"
)

func TestParse(t *testing.T){
	type TestCase struct {
		addr string
		mask string
		expect string
	}

	tc := []TestCase{
		{addr: "0.0.0.0", mask: "0.0.0.0", expect: "0.0.0.0/0"},
		{addr: "172.23.14.10", mask: "255.255.254.0", expect: "172.23.14.10/23"},
		{addr: "172.23.14.10", mask: "255.255.251.0", expect: "172.23.14.10/23"},
	}


	for _, test := range tc {
		s, _ := Parse(test.addr, test.mask)
		if s.String() != test.expect {
			t.Error("Error parsing", test.addr,"and", test.mask, "Expected:", test.expect, "Got:", s.String())
		}
	}
		
	
}