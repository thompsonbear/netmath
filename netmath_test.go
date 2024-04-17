package netmath

import (
	"testing"
)

func TestParse(t *testing.T){
	parseTests := []struct{
		addr string
		mask string
		want string
	}{
		// Lowest/Highest Valid Values
		{addr: "0.0.0.0", mask: "0.0.0.0", want: "0.0.0.0/0"},
		{addr: "255.255.255.255", mask: "255.255.255.255", want: "255.255.255.255/32"},
		{addr: "::", mask: "::", want: "::/0"},
		{addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},

		//IP Version Mix
		{addr: "::", mask: "255.255.255.255", want: "::/32"}, 
		{addr: "::", mask: "0.0.0.0", want: "::/0"},
		{addr: "255.255.255.255", mask: "::", want: "255.255.255.255/0"},
		{addr: "255.255.255.255", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: "invalid Prefix"}, //128 Bits out of range for IPv4

		// Invalid Host
		{addr: "-1.0.0.0", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "0.-1.0.0", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "0.0.-1.0", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "0.0.0.-1", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "255.255.255.256", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "255.255.256.255", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "255.256.255.255", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "256.255.255.255", mask: "0.0.0.0", want: "invalid host address"},
		{addr: "0.0.0", mask: "0.0.0.0", want: "invalid host address"}, //Length error 
		{addr: "255.255.255", mask: "0.0.0.0", want: "invalid host address"}, //Length error
		{addr: "0.0.0.", mask: "0.0.0.0", want: "invalid host address"}, //Length error 
		{addr: "255.255.255.", mask: "0.0.0.0", want: "invalid host address"}, //Length error

		//Invalid Mask
		{addr: "0.0.0.0", mask: "255.255.255.256", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "255.255.256.255", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "255.256.255.255", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "256.255.255.255", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "0.0.0.-1", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "0.0.-1.0", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "0.-1.0.0", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "-1.0.0.0", want: "invalid subnet mask"}, //Out of range error
		{addr: "0.0.0.0", mask: "255.255.255.251", want: "invalid subnet mask"}, // Sub-Byte error
		{addr: "0.0.0.0", mask: "255.255.0.255", want: "invalid subnet mask"}, // Byte error
		{addr: "0.0.0.0", mask: "255.255.255", want: "invalid subnet mask"}, // Length error
		{addr: "0.0.0.0", mask: "255.255.255.", want: "invalid subnet mask"}, // Length error

		// Common random
		{addr: "192.168.0.0", mask: "255.255.255.0", want: "192.168.0.0/24"},
		{addr: "172.16.0.0", mask: "255.255.248.0", want: "172.16.0.0/21"},
		{addr: "10.0.0.0", mask: "255.254.0.0", want: "10.0.0.0/15"},
		{addr: "10.0.0.0", mask: "255.0.0.0", want: "10.0.0.0/8"},
		{addr: "200.215.3.4", mask: "128.0.0.0", want: "200.215.3.4/1"},
	}

	for _, test := range parseTests {
		s, err := Parse(test.addr, test.mask)

		if err != nil {
			if err.Error() != test.want {
				t.Error("Error parsing", test.addr,"and", test.mask, "Expected:", test.want, "Got:", s.String(), "With Error:", err)
			}
		} else if s.String() != test.want {
			t.Error("Error parsing", test.addr,"and", test.mask, "Expected:", test.want, "Got:", s.String())
		}
	}
}

func TestMask(t *testing.T) {
	maskTests := []struct {
		snet string
		want string
	}{
		// IPV4
		{snet: "0.0.0.0/1", want: "128.0.0.0"},
		{snet: "0.0.0.0/2", want: "192.0.0.0"},
		{snet: "0.0.0.0/3", want: "224.0.0.0"},
		{snet: "0.0.0.0/4", want: "240.0.0.0"},
		{snet: "0.0.0.0/5", want: "248.0.0.0"},
		{snet: "0.0.0.0/6", want: "252.0.0.0"},
		{snet: "0.0.0.0/7", want: "254.0.0.0"},
		{snet: "0.0.0.0/8", want: "255.0.0.0"},
		{snet: "0.0.0.0/9", want: "255.128.0.0"},
		{snet: "0.0.0.0/10", want: "255.192.0.0"},
		{snet: "0.0.0.0/11", want: "255.224.0.0"},
		{snet: "0.0.0.0/12", want: "255.240.0.0"},
		{snet: "0.0.0.0/13", want: "255.248.0.0"},
		{snet: "0.0.0.0/14", want: "255.252.0.0"},
		{snet: "0.0.0.0/15", want: "255.254.0.0"},
		{snet: "0.0.0.0/16", want: "255.255.0.0"},
		{snet: "0.0.0.0/17", want: "255.255.128.0"},
		{snet: "0.0.0.0/18", want: "255.255.192.0"},
		{snet: "0.0.0.0/19", want: "255.255.224.0"},
		{snet: "0.0.0.0/20", want: "255.255.240.0"},
		{snet: "0.0.0.0/21", want: "255.255.248.0"},
		{snet: "0.0.0.0/22", want: "255.255.252.0"},
		{snet: "0.0.0.0/23", want: "255.255.254.0"},
		{snet: "0.0.0.0/24", want: "255.255.255.0"},
		{snet: "0.0.0.0/25", want: "255.255.255.128"},
		{snet: "0.0.0.0/26", want: "255.255.255.192"},
		{snet: "0.0.0.0/27", want: "255.255.255.224"},
		{snet: "0.0.0.0/28", want: "255.255.255.240"},
		{snet: "0.0.0.0/29", want: "255.255.255.248"},
		{snet: "0.0.0.0/30", want: "255.255.255.252"},
		{snet: "0.0.0.0/31", want: "255.255.255.254"},
		{snet: "0.0.0.0/32", want: "255.255.255.255"},

		// IPV6
		{snet: "::/1", want: "8000::"},
		{snet: "::/2", want: "c000::"},
		{snet: "::/3", want: "e000::"},
		{snet: "::/4", want: "f000::"},
		{snet: "::/5", want: "f800::"},
		{snet: "::/6", want: "fc00::"},
		{snet: "::/7", want: "fe00::"},
		{snet: "::/8", want: "ff00::"},
		{snet: "::/9", want: "ff80::"},
		{snet: "::/10", want: "ffc0::"},
		{snet: "::/11", want: "ffe0::"},
		{snet: "::/12", want: "fff0::"},
		{snet: "::/13", want: "fff8::"},
		{snet: "::/14", want: "fffc::"},
		{snet: "::/15", want: "fffe::"},
		{snet: "::/16", want: "ffff::"},
		{snet: "::/17", want: "ffff:8000::"},
		{snet: "::/18", want: "ffff:c000::"},
		{snet: "::/19", want: "ffff:e000::"},
		{snet: "::/20", want: "ffff:f000::"},
		{snet: "::/21", want: "ffff:f800::"},
		{snet: "::/22", want: "ffff:fc00::"},
		{snet: "::/23", want: "ffff:fe00::"},
		{snet: "::/24", want: "ffff:ff00::"},
		{snet: "::/25", want: "ffff:ff80::"},
		{snet: "::/26", want: "ffff:ffc0::"},
		{snet: "::/27", want: "ffff:ffe0::"},
		{snet: "::/28", want: "ffff:fff0::"},
		{snet: "::/29", want: "ffff:fff8::"},
		{snet: "::/30", want: "ffff:fffc::"},
		{snet: "::/31", want: "ffff:fffe::"},
		{snet: "::/32", want: "ffff:ffff::"},
		{snet: "::/33", want: "ffff:ffff:8000::"},
		{snet: "::/34", want: "ffff:ffff:c000::"},
		{snet: "::/35", want: "ffff:ffff:e000::"},
		{snet: "::/36", want: "ffff:ffff:f000::"},
		{snet: "::/37", want: "ffff:ffff:f800::"},
		{snet: "::/38", want: "ffff:ffff:fc00::"},
		{snet: "::/39", want: "ffff:ffff:fe00::"},
		{snet: "::/40", want: "ffff:ffff:ff00::"},
		{snet: "::/41", want: "ffff:ffff:ff80::"},
		{snet: "::/42", want: "ffff:ffff:ffc0::"},
		{snet: "::/43", want: "ffff:ffff:ffe0::"},
		{snet: "::/44", want: "ffff:ffff:fff0::"},
		{snet: "::/45", want: "ffff:ffff:fff8::"},
		{snet: "::/46", want: "ffff:ffff:fffc::"},
		{snet: "::/47", want: "ffff:ffff:fffe::"},
		{snet: "::/48", want: "ffff:ffff:ffff::"},
		{snet: "::/49", want: "ffff:ffff:ffff:8000::"},
		{snet: "::/50", want: "ffff:ffff:ffff:c000::"},
		{snet: "::/51", want: "ffff:ffff:ffff:e000::"},
		{snet: "::/52", want: "ffff:ffff:ffff:f000::"},
		{snet: "::/53", want: "ffff:ffff:ffff:f800::"},
		{snet: "::/54", want: "ffff:ffff:ffff:fc00::"},
		{snet: "::/55", want: "ffff:ffff:ffff:fe00::"},
		{snet: "::/56", want: "ffff:ffff:ffff:ff00::"},
		{snet: "::/57", want: "ffff:ffff:ffff:ff80::"},
		{snet: "::/58", want: "ffff:ffff:ffff:ffc0::"},
		{snet: "::/59", want: "ffff:ffff:ffff:ffe0::"},
		{snet: "::/60", want: "ffff:ffff:ffff:fff0::"},
		{snet: "::/61", want: "ffff:ffff:ffff:fff8::"},
		{snet: "::/62", want: "ffff:ffff:ffff:fffc::"},
		{snet: "::/63", want: "ffff:ffff:ffff:fffe::"},
		{snet: "::/64", want: "ffff:ffff:ffff:ffff::"},
		{snet: "::/65", want: "ffff:ffff:ffff:ffff:8000::"},
		{snet: "::/66", want: "ffff:ffff:ffff:ffff:c000::"},
		{snet: "::/67", want: "ffff:ffff:ffff:ffff:e000::"},
		{snet: "::/68", want: "ffff:ffff:ffff:ffff:f000::"},
		{snet: "::/69", want: "ffff:ffff:ffff:ffff:f800::"},
		{snet: "::/70", want: "ffff:ffff:ffff:ffff:fc00::"},
		{snet: "::/71", want: "ffff:ffff:ffff:ffff:fe00::"},
		{snet: "::/72", want: "ffff:ffff:ffff:ffff:ff00::"},
		{snet: "::/73", want: "ffff:ffff:ffff:ffff:ff80::"},
		{snet: "::/74", want: "ffff:ffff:ffff:ffff:ffc0::"},
		{snet: "::/75", want: "ffff:ffff:ffff:ffff:ffe0::"},
		{snet: "::/76", want: "ffff:ffff:ffff:ffff:fff0::"},
		{snet: "::/77", want: "ffff:ffff:ffff:ffff:fff8::"},
		{snet: "::/78", want: "ffff:ffff:ffff:ffff:fffc::"},
		{snet: "::/79", want: "ffff:ffff:ffff:ffff:fffe::"},
		{snet: "::/80", want: "ffff:ffff:ffff:ffff:ffff::"},
		{snet: "::/81", want: "ffff:ffff:ffff:ffff:ffff:8000::"},
		{snet: "::/82", want: "ffff:ffff:ffff:ffff:ffff:c000::"},
		{snet: "::/83", want: "ffff:ffff:ffff:ffff:ffff:e000::"},
		{snet: "::/84", want: "ffff:ffff:ffff:ffff:ffff:f000::"},
		{snet: "::/85", want: "ffff:ffff:ffff:ffff:ffff:f800::"},
		{snet: "::/86", want: "ffff:ffff:ffff:ffff:ffff:fc00::"},
		{snet: "::/87", want: "ffff:ffff:ffff:ffff:ffff:fe00::"},
		{snet: "::/88", want: "ffff:ffff:ffff:ffff:ffff:ff00::"},
		{snet: "::/89", want: "ffff:ffff:ffff:ffff:ffff:ff80::"},
		{snet: "::/90", want: "ffff:ffff:ffff:ffff:ffff:ffc0::"},
		{snet: "::/91", want: "ffff:ffff:ffff:ffff:ffff:ffe0::"},
		{snet: "::/92", want: "ffff:ffff:ffff:ffff:ffff:fff0::"},
		{snet: "::/93", want: "ffff:ffff:ffff:ffff:ffff:fff8::"},
		{snet: "::/94", want: "ffff:ffff:ffff:ffff:ffff:fffc::"},
		{snet: "::/95", want: "ffff:ffff:ffff:ffff:ffff:fffe::"},
		{snet: "::/96", want: "ffff:ffff:ffff:ffff:ffff:ffff::"},
		{snet: "::/97", want: "ffff:ffff:ffff:ffff:ffff:ffff:8000:0"},
		{snet: "::/98", want: "ffff:ffff:ffff:ffff:ffff:ffff:c000:0"},
		{snet: "::/99", want: "ffff:ffff:ffff:ffff:ffff:ffff:e000:0"},
		{snet: "::/100", want: "ffff:ffff:ffff:ffff:ffff:ffff:f000:0"},
		{snet: "::/101", want: "ffff:ffff:ffff:ffff:ffff:ffff:f800:0"},
		{snet: "::/102", want: "ffff:ffff:ffff:ffff:ffff:ffff:fc00:0"},
		{snet: "::/103", want: "ffff:ffff:ffff:ffff:ffff:ffff:fe00:0"},
		{snet: "::/104", want: "ffff:ffff:ffff:ffff:ffff:ffff:ff00:0"},
		{snet: "::/105", want: "ffff:ffff:ffff:ffff:ffff:ffff:ff80:0"},
		{snet: "::/106", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffc0:0"},
		{snet: "::/107", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffe0:0"},
		{snet: "::/108", want: "ffff:ffff:ffff:ffff:ffff:ffff:fff0:0"},
		{snet: "::/109", want: "ffff:ffff:ffff:ffff:ffff:ffff:fff8:0"},
		{snet: "::/110", want: "ffff:ffff:ffff:ffff:ffff:ffff:fffc:0"},
		{snet: "::/111", want: "ffff:ffff:ffff:ffff:ffff:ffff:fffe:0"},
		{snet: "::/112", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"},
		{snet: "::/113", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000"},
		{snet: "::/114", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:c000"},
		{snet: "::/115", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:e000"},
		{snet: "::/116", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:f000"},
		{snet: "::/117", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:f800"},
		{snet: "::/118", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00"},
		{snet: "::/119", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00"},
		{snet: "::/120", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{snet: "::/121", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80"},
		{snet: "::/122", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0"},
		{snet: "::/123", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0"},
		{snet: "::/124", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0"},
		{snet: "::/125", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8"},
		{snet: "::/126", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"},
		{snet: "::/127", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
		{snet: "::/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}

	for _, test := range maskTests {
		s, _ := ParseCIDR(test.snet)
		c, err := s.Mask()
		if c.String() != test.want {
			t.Error("Error getting .Mask() for", s.String(), "Want", test.want, "Got", c, "With Error:", err)
		}
	}
}

func TestNetwork(t *testing.T) {
	networkTests := []struct{
		snet string
		want string
	}{
		{snet: "192.168.20.15/23", want: "192.168.20.0"},
		{snet: "192.168.21.200/23", want: "192.168.20.0"},
		{snet: "10.0.0.0/8", want: "10.0.0.0"},
        {snet: "172.16.0.0/16", want: "172.16.0.0"},
        {snet: "192.168.0.0/24", want: "192.168.0.0"},
		{snet: "10.255.255.255/8", want: "10.0.0.0"},
        {snet: "172.16.255.255/16", want: "172.16.0.0"},
        {snet: "192.168.0.255/24", want: "192.168.0.0"},
        {snet: "255.255.255.255/1", want: "128.0.0.0"},
        {snet: "255.255.255.255/32", want: "255.255.255.255"},
		{snet: "::/128", want: "::"},
		{snet: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{snet: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/1", want: "8000::"},
	}

	for _, test := range networkTests {
		s, _ := ParseCIDR(test.snet)
		n, err := s.Network()
		if err != nil {
			t.Error("Error getting .Network() for", test.snet, "Error:", err)
		}

		if n.String() != test.want {
			t.Error("Error getting .Network() for", test.snet, "Expected:", test.want, "Got:", n.String())
		}
	}
}

func TestBroadcast(t *testing.T) {
	broadcastTests := []struct{
		snet string
		want string
	}{
		{snet: "192.168.20.15/23", want: "192.168.21.255"},
		{snet: "192.168.21.200/23", want: "192.168.21.255"},
		{snet: "10.0.0.0/8", want: "10.255.255.255"},
        {snet: "172.16.0.0/16", want: "172.16.255.255"},
        {snet: "192.168.0.0/24", want: "192.168.0.255"},
		{snet: "10.255.255.255/8", want: "10.255.255.255"},
        {snet: "172.16.255.255/16", want: "172.16.255.255"},
        {snet: "192.168.0.255/24", want: "192.168.0.255"},
        {snet: "255.255.255.255/1", want: "255.255.255.255"},
        {snet: "255.255.255.255/32", want: "255.255.255.255"},
		{snet: "::/128", want: "::"},
		{snet: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{snet: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/1", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}

	for _, test := range broadcastTests {
		s, _ := ParseCIDR(test.snet)
		b, err := s.Broadcast()
		if err != nil {
			t.Error("Error getting .Broadcast() for", test.snet, "Error:", err)
		}

		if b.String() != test.want {
			t.Error("Error getting .Broadcast() for", test.snet, "Expected:", test.want, "Got:", b.String())
		}
	}
}

func TestListAll(t *testing.T){
	listTests := []struct{
		snet string
		want []string
	}{
		{snet: "0.0.0.0/8", want: []string{"0.0.0.0/8"}},
		{snet: "0.0.0.0/7", want: []string{"0.0.0.0/7","2.0.0.0/7","4.0.0.0/7","6.0.0.0/7","8.0.0.0/7","10.0.0.0/7","12.0.0.0/7","14.0.0.0/7","16.0.0.0/7","18.0.0.0/7","20.0.0.0/7","22.0.0.0/7","24.0.0.0/7","26.0.0.0/7","28.0.0.0/7","30.0.0.0/7","32.0.0.0/7","34.0.0.0/7","36.0.0.0/7","38.0.0.0/7","40.0.0.0/7","42.0.0.0/7","44.0.0.0/7","46.0.0.0/7","48.0.0.0/7","50.0.0.0/7","52.0.0.0/7","54.0.0.0/7","56.0.0.0/7","58.0.0.0/7","60.0.0.0/7","62.0.0.0/7","64.0.0.0/7","66.0.0.0/7","68.0.0.0/7","70.0.0.0/7","72.0.0.0/7","74.0.0.0/7","76.0.0.0/7","78.0.0.0/7","80.0.0.0/7","82.0.0.0/7","84.0.0.0/7","86.0.0.0/7","88.0.0.0/7","90.0.0.0/7","92.0.0.0/7","94.0.0.0/7","96.0.0.0/7","98.0.0.0/7","100.0.0.0/7","102.0.0.0/7","104.0.0.0/7","106.0.0.0/7","108.0.0.0/7","110.0.0.0/7","112.0.0.0/7","114.0.0.0/7","116.0.0.0/7","118.0.0.0/7","120.0.0.0/7","122.0.0.0/7","124.0.0.0/7","126.0.0.0/7","128.0.0.0/7","130.0.0.0/7","132.0.0.0/7","134.0.0.0/7","136.0.0.0/7","138.0.0.0/7","140.0.0.0/7","142.0.0.0/7","144.0.0.0/7","146.0.0.0/7","148.0.0.0/7","150.0.0.0/7","152.0.0.0/7","154.0.0.0/7","156.0.0.0/7","158.0.0.0/7","160.0.0.0/7","162.0.0.0/7","164.0.0.0/7","166.0.0.0/7","168.0.0.0/7","170.0.0.0/7","172.0.0.0/7","174.0.0.0/7","176.0.0.0/7","178.0.0.0/7","180.0.0.0/7","182.0.0.0/7","184.0.0.0/7","186.0.0.0/7","188.0.0.0/7","190.0.0.0/7","192.0.0.0/7","194.0.0.0/7","196.0.0.0/7","198.0.0.0/7","200.0.0.0/7","202.0.0.0/7","204.0.0.0/7","206.0.0.0/7","208.0.0.0/7","210.0.0.0/7","212.0.0.0/7","214.0.0.0/7","216.0.0.0/7","218.0.0.0/7","220.0.0.0/7","222.0.0.0/7","224.0.0.0/7","226.0.0.0/7","228.0.0.0/7","230.0.0.0/7","232.0.0.0/7","234.0.0.0/7","236.0.0.0/7","238.0.0.0/7","240.0.0.0/7","242.0.0.0/7","244.0.0.0/7","246.0.0.0/7","248.0.0.0/7","250.0.0.0/7","252.0.0.0/7","254.0.0.0/7"}},
		{snet: "0.0.0.0/4", want: []string{"0.0.0.0/4","16.0.0.0/4","32.0.0.0/4","48.0.0.0/4","64.0.0.0/4","80.0.0.0/4","96.0.0.0/4","112.0.0.0/4","128.0.0.0/4","144.0.0.0/4","160.0.0.0/4","176.0.0.0/4","192.0.0.0/4","208.0.0.0/4","224.0.0.0/4","240.0.0.0/4"}},
		{snet: "::/8", want: []string{"::/8"}},
		{snet: "::/7", want: []string{"::/7","200::/7","400::/7","600::/7","800::/7","a00::/7","c00::/7","e00::/7","1000::/7","1200::/7","1400::/7","1600::/7","1800::/7","1a00::/7","1c00::/7","1e00::/7","2000::/7","2200::/7","2400::/7","2600::/7","2800::/7","2a00::/7","2c00::/7","2e00::/7","3000::/7","3200::/7","3400::/7","3600::/7","3800::/7","3a00::/7","3c00::/7","3e00::/7","4000::/7","4200::/7","4400::/7","4600::/7","4800::/7","4a00::/7","4c00::/7","4e00::/7","5000::/7","5200::/7","5400::/7","5600::/7","5800::/7","5a00::/7","5c00::/7","5e00::/7","6000::/7","6200::/7","6400::/7","6600::/7","6800::/7","6a00::/7","6c00::/7","6e00::/7","7000::/7","7200::/7","7400::/7","7600::/7","7800::/7","7a00::/7","7c00::/7","7e00::/7","8000::/7","8200::/7","8400::/7","8600::/7","8800::/7","8a00::/7","8c00::/7","8e00::/7","9000::/7","9200::/7","9400::/7","9600::/7","9800::/7","9a00::/7","9c00::/7","9e00::/7","a000::/7","a200::/7","a400::/7","a600::/7","a800::/7","aa00::/7","ac00::/7","ae00::/7","b000::/7","b200::/7","b400::/7","b600::/7","b800::/7","ba00::/7","bc00::/7","be00::/7","c000::/7","c200::/7","c400::/7","c600::/7","c800::/7","ca00::/7","cc00::/7","ce00::/7","d000::/7","d200::/7","d400::/7","d600::/7","d800::/7","da00::/7","dc00::/7","de00::/7","e000::/7","e200::/7","e400::/7","e600::/7","e800::/7","ea00::/7","ec00::/7","ee00::/7","f000::/7","f200::/7","f400::/7","f600::/7","f800::/7","fa00::/7","fc00::/7","fe00::/7"}},
		{snet: "::/4", want: []string{"::/4","1000::/4","2000::/4","3000::/4","4000::/4","5000::/4","6000::/4","7000::/4","8000::/4","9000::/4","a000::/4","b000::/4","c000::/4","d000::/4","e000::/4","f000::/4"}},
	}

	for _, test := range listTests {
		s, _ := ParseCIDR(test.snet)
		list := s.ListAll()
		if len(test.want) == len(list) {
			for i := 0; i < len(list); i++ {
				if list[i].String() != test.want[i] {
					t.Error("Error getting .ListAll() for", test.snet, "Expected:", test.want[i], "Got:", list[i])
				}
			}
		} else {
			t.Error("Error getting .ListAll() for", test.snet, "Error: Lengths do not match. Want", len(test.want),"Got",len(list))
		}
		

		
	}
}

func TestCount(t *testing.T){
	countTests := []struct {
		snet string
		want float64
	} {
		//IPV4
		{snet: "0.0.0.0/0", want: 4_294_967_296},
		{snet: "0.0.0.0/1", want: 2_147_483_648},
		{snet: "0.0.0.0/2", want: 1_073_741_824},
		{snet: "0.0.0.0/3", want: 536_870_912},
		{snet: "0.0.0.0/4", want: 268_435_456},
		{snet: "0.0.0.0/5", want: 134_217_728},
		{snet: "0.0.0.0/6", want: 67_108_864},
		{snet: "0.0.0.0/7", want: 33_554_432},
		{snet: "0.0.0.0/8", want: 16_777_216},
		{snet: "0.0.0.0/9", want: 8_388_608},
		{snet: "0.0.0.0/10", want: 4_194_304},
		{snet: "0.0.0.0/11", want: 2_097_152},
		{snet: "0.0.0.0/12", want: 1_048_576},
		{snet: "0.0.0.0/13", want: 524_288},
		{snet: "0.0.0.0/14", want: 262_144},
		{snet: "0.0.0.0/15", want: 131_072},
		{snet: "0.0.0.0/16", want: 65_536},
		{snet: "0.0.0.0/17", want: 32_768},
		{snet: "0.0.0.0/18", want: 16_384},
		{snet: "0.0.0.0/19", want: 8_192},
		{snet: "0.0.0.0/20", want: 4_096},
		{snet: "0.0.0.0/21", want: 2_048},
		{snet: "0.0.0.0/22", want: 1_024},
		{snet: "0.0.0.0/23", want: 512},
		{snet: "0.0.0.0/24", want: 256},
		{snet: "0.0.0.0/25", want: 128},
		{snet: "0.0.0.0/26", want: 64},
		{snet: "0.0.0.0/27", want: 32},
		{snet: "0.0.0.0/28", want: 16},
		{snet: "0.0.0.0/29", want: 8},
		{snet: "0.0.0.0/30", want: 4},
		{snet: "0.0.0.0/31", want: 2},
		{snet: "0.0.0.0/32", want: 1},

		//IPV6
		{snet: "::/0", want: 340_282_366_920_938_463_462_382_045_406_240_211_456},
		{snet: "::/1", want: 170_141_183_460_469_231_731_687_303_715_884_105_728},
		{snet: "::/2", want: 85_070_591_730_234_615_865_843_651_857_942_052_864},
		{snet: "::/3", want: 42_535_295_865_117_307_932_921_825_928_971_026_432},
		{snet: "::/4", want: 21_267_647_932_558_653_964_609_129_644_855_132_160},
		{snet: "::/5", want: 10_633_823_966_279_326_983_230_456_482_242_756_608},
		{snet: "::/6", want: 5_316_911_983_139_663_491_615_228_241_121_378_304},
		{snet: "::/7", want: 2_658_455_991_569_831_745_807_614_120_560_689_152},
		{snet: "::/8", want: 1_329_227_995_784_915_872_903_807_060_280_344_576},
		{snet: "::/9", want: 664_613_997_892_457_936_451_903_530_140_172_288},
		{snet: "::/10", want: 332_306_998_946_228_968_225_951_765_070_086_144},
		{snet: "::/11", want: 166_153_499_473_114_484_112_975_882_535_043_072},
		{snet: "::/12", want: 83_076_749_736_557_242_056_487_941_267_521_536},
		{snet: "::/13", want: 41_538_374_868_278_621_028_243_970_633_760_768},
		{snet: "::/14", want: 20_769_187_434_139_310_514_121_985_316_880_384},
		{snet: "::/15", want: 10_384_593_717_069_655_257_060_992_658_440_192},
		{snet: "::/16", want: 5_192_296_858_534_827_628_530_496_329_220_096},
		{snet: "::/17", want: 2_596_148_429_267_413_814_132_762_481_604_864},
		{snet: "::/18", want: 1_298_074_214_633_706_907_132_624_082_305_024},
		{snet: "::/19", want: 649_037_107_316_853_453_566_312_041_152_512},
		{snet: "::/20", want: 324_518_553_658_426_726_783_156_020_576_256},
		{snet: "::/21", want: 162_259_276_829_213_363_391_578_010_288_128},
		{snet: "::/22", want: 81_129_638_414_606_681_695_789_005_144_064},
		{snet: "::/23", want: 40_564_819_207_303_340_847_894_502_572_032},
		{snet: "::/24", want: 20_282_409_603_651_670_423_947_251_286_016},
		{snet: "::/25", want: 10_141_204_801_825_835_211_973_625_643_008},
		{snet: "::/26", want: 5_070_602_400_912_917_605_986_812_821_504},
		{snet: "::/27", want: 2_535_301_200_456_458_802_993_406_410_752},
		{snet: "::/28", want: 1_267_650_600_228_229_401_496_703_205_376},
		{snet: "::/29", want: 633_825_300_114_114_700_748_351_602_688},
		{snet: "::/30", want: 316_912_650_057_057_350_374_175_801_344},
		{snet: "::/31", want: 158_456_325_028_528_675_187_087_900_672},
		{snet: "::/32", want: 79_228_162_514_264_337_593_543_950_336},
		{snet: "::/33", want: 39_614_081_257_132_168_796_771_975_168},
		{snet: "::/34", want: 19_807_040_628_566_084_398_385_987_584},
		{snet: "::/35", want: 9_903_520_314_283_042_199_192_993_792},
		{snet: "::/36", want: 4_951_760_157_141_521_099_598_498_896},
		{snet: "::/37", want: 2_475_880_078_570_760_549_799_124_224},
		{snet: "::/38", want: 1_237_940_039_285_380_270_489_912_112},
		{snet: "::/39", want: 618_970_019_642_690_137_449_562_112},
		{snet: "::/40", want: 309_485_009_821_345_068_724_781_056},
		{snet: "::/41", want: 154_742_504_910_672_534_362_390_528},
		{snet: "::/42", want: 77_371_252_455_336_267_181_195_264},
		{snet: "::/43", want: 38_685_626_227_668_133_590_597_632},
		{snet: "::/44", want: 19_342_813_113_834_066_795_298_816},
		{snet: "::/45", want: 9_671_406_556_917_033_397_649_408},
		{snet: "::/46", want: 4_835_703_278_458_516_698_824_704},
		{snet: "::/47", want: 2_417_851_639_229_258_349_412_352},
		{snet: "::/48", want: 1_208_925_819_614_629_174_706_176},
		{snet: "::/49", want: 604_462_909_807_314_587_353_088},
		{snet: "::/50", want: 302_231_454_903_657_293_676_544},
		{snet: "::/51", want: 151_115_727_451_828_646_838_272},
		{snet: "::/52", want: 75_557_863_725_914_323_419_136},
		{snet: "::/53", want: 37_778_931_862_957_161_709_568},
		{snet: "::/54", want: 18_889_465_931_478_580_854_784},
		{snet: "::/55", want: 9_444_732_965_739_290_427_392},
		{snet: "::/56", want: 4_722_366_482_869_645_213_696},
		{snet: "::/57", want: 2_361_183_241_434_822_606_848},
		{snet: "::/58", want: 1_180_591_620_717_411_303_424},
		{snet: "::/59", want: 590_295_810_358_705_651_712},
		{snet: "::/60", want: 295_147_905_179_352_825_856},
		{snet: "::/61", want: 147_573_952_589_676_412_928},
		{snet: "::/62", want: 73_786_976_294_838_206_464},
		{snet: "::/63", want: 36_893_488_147_419_103_232},
		{snet: "::/64", want: 18_446_744_073_709_551_616},
		{snet: "::/65", want: 9_223_372_036_854_775_808},
		{snet: "::/66", want: 4_611_686_018_427_387_904},
		{snet: "::/67", want: 2_305_843_009_213_693_952},
		{snet: "::/68", want: 1_152_921_504_606_846_976},
		{snet: "::/69", want: 576_460_752_303_423_488},
		{snet: "::/70", want: 288_230_376_151_711_744},
		{snet: "::/71", want: 144_115_188_075_855_872},
		{snet: "::/72", want: 72_057_594_037_927_936},
		{snet: "::/73", want: 36_028_797_018_963_968},
		{snet: "::/74", want: 18_014_398_509_481_984},
		{snet: "::/75", want: 9_007_199_254_740_992},
		{snet: "::/76", want: 4_503_599_627_370_496},
		{snet: "::/77", want: 2_251_799_813_685_248},
		{snet: "::/78", want: 1_125_899_906_842_624},
		{snet: "::/79", want: 562_949_953_421_312},
		{snet: "::/80", want: 281_474_976_710_656},
		{snet: "::/81", want: 140_737_488_355_328},
		{snet: "::/82", want: 70_368_744_177_664},
		{snet: "::/83", want: 35_184_372_088_832},
		{snet: "::/84", want: 17_592_186_044_416},
		{snet: "::/85", want: 8_796_093_022_208},
		{snet: "::/86", want: 4_398_046_511_104},
		{snet: "::/87", want: 2_199_023_255_552},
		{snet: "::/88", want: 1_099_511_627_776},
		{snet: "::/89", want: 549_755_813_888},
		{snet: "::/90", want: 274_877_906_944},
		{snet: "::/91", want: 137_438_953_472},
		{snet: "::/92", want: 68_719_476_736},
		{snet: "::/93", want: 34_359_738_368},
		{snet: "::/94", want: 17_179_869_184},
		{snet: "::/95", want: 8_589_934_592},
		{snet: "::/96", want: 4_294_967_296},
		{snet: "::/97", want: 2_147_483_648},
		{snet: "::/98", want: 1_073_741_824},
		{snet: "::/99", want: 536_870_912},
		{snet: "::/100", want: 268_435_456},
		{snet: "::/101", want: 134_217_728},
		{snet: "::/102", want: 67_108_864},
		{snet: "::/103", want: 33_554_432},
		{snet: "::/104", want: 16_777_216},
		{snet: "::/105", want: 8_388_608},
		{snet: "::/106", want: 4_194_304},
		{snet: "::/107", want: 2_097_152},
		{snet: "::/108", want: 1_048_576},
		{snet: "::/109", want: 524_288},
		{snet: "::/110", want: 262_144},
		{snet: "::/111", want: 131_072},
		{snet: "::/112", want: 65_536},
		{snet: "::/113", want: 32_768},
		{snet: "::/114", want: 16_384},
		{snet: "::/115", want: 8_192},
		{snet: "::/116", want: 4_096},
		{snet: "::/117", want: 2_048},
		{snet: "::/118", want: 1_024},
		{snet: "::/119", want: 512},
		{snet: "::/120", want: 256},
		{snet: "::/121", want: 128},
		{snet: "::/122", want: 64},
		{snet: "::/123", want: 32},
		{snet: "::/124", want: 16},
		{snet: "::/125", want: 8},
		{snet: "::/126", want: 4},
		{snet: "::/127", want: 2},
		{snet: "::/128", want: 1},
	}

	for _, test := range countTests {
		s, _ := ParseCIDR(test.snet)
		c, err := s.Count()
		if c != test.want {
			t.Error("Error getting .Count() for", s.String(),"Want",test.want,"Got",c,"With Error:",err)
		}
	}
}
