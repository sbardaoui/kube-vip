package forwarder

import (
	"context"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func startNFTables(ctx context.Context, srcAddress string, srcPort int, destAddress string, destPort int) error {
	//TODO adding support for ipv6
	if strings.Contains(srcAddress, ":") {
		log.Fatal("IPV6 forwarding isn't yet supported. Feel free to contribute.")
	}
	ensureCtx, ensureCancel := context.WithCancel(ctx)
	defer ensureCancel()
	for {
		select {
		case <-ensureCtx.Done():
			c := &nftables.Conn{}
			t, err := c.ListTables()
			if err != nil {
				return err
			}
			for _, elem := range t {
				if elem.Name == "KUBE-VIP" {
					log.Infoln("cleaning table")
					err := teardownNFTables(c, elem)
					if err != nil {
						log.Errorf("failed to tear down table")
					}

				}
			}
			return nil
		default:
			//creating the connection
			c, err := ForwardRules(srcAddress, srcPort, destAddress, destPort)
			if err != nil {
				log.Infoln("failed at forward rules")
				return err
			}
			return c.Flush()
		}
	}
}

func stopNFTables(srcAddress string, srcPort int, destAddress string, destPort int) error {
	c, err := ForwardRules(srcAddress, srcPort, destAddress, destPort)
	if err != nil {
		log.Errorf("failed to create forward rules")
		return err
	}
	// fetch the table t
	t, err := c.ListTables()
	if err != nil {
		log.Errorf("failed to fetch tables")
		return err
	}
	for _, elem := range t {
		if elem.Name == "KUBE-VIP" {
			err := teardownNFTables(c, elem)
			if err != nil {
				log.Errorf("failed to tear down table")
			}
		}
	}
	return c.Flush()
}

func ForwardRules(srcAddress string, srcPort int, destAddress string, destPort int) (*nftables.Conn, error) {
	c := &nftables.Conn{}
	//creating the table to use for the chain
	kubeForwarder := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "KUBE-VIP",
	}
	kubeForwarder = c.AddTable(kubeForwarder)
	log.Infoln("table created")
	prerouting := c.AddChain(&nftables.Chain{
		Name:     "PREROUTING",
		Table:    kubeForwarder,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})
	postrouting := c.AddChain(&nftables.Chain{
		Name:     "POSTROUTING",
		Table:    kubeForwarder,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Type:     nftables.ChainTypeNAT,
	})
	output := c.AddChain(&nftables.Chain{
		Name:     "OUTPUT",
		Table:    kubeForwarder,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})
	//creating the sets containing the ip addresses
	log.Infoln("chains created")
	// finishing the rule to make the function work
	c.AddRule(&nftables.Rule{
		Table: kubeForwarder,
		Chain: prerouting,
		Exprs: []expr.Any{

			//payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			//cmp eq reg 1
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP(srcAddress).To4(),
			},
			//meta load l4proto => reg 1
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},

			//cmp eq reg 1 0x00000006
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			//payload load 2b @ transport header + 2 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},

			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(srcPort)),
			},

			//immediate reg 1 0x0202a8c0
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP(destAddress).To4(),
			},

			//immediate reg 2 0x00005000
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(uint16(destPort)),
			},
			//nat dnat ip addr_min reg 1 proto_min reg 2
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				Random:      true,
			},
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: kubeForwarder,
		Chain: postrouting,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			//payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},

			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP(destAddress).To4(),
			},
			// meta load l4proto => reg 1
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// cmp eq reg 1 0x00000006
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			//payload load 2b @ transport header + 2 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			//cmp eq reg 1 0x00005000
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(destPort)),
			},
			//masq
			&expr.Masq{Random: true},

			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: kubeForwarder,
		Chain: output,
		Exprs: []expr.Any{
			//payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			//cmp eq reg 1
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP(srcAddress).To4(),
			},
			//meta load l4proto => reg 1
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},

			//cmp eq reg 1
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			//payload load 2b @ transport header + 2 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(srcPort)),
			},

			//immediate reg 1 0x0202a8c0
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP(destAddress).To4(),
			},

			//immediate reg 2 0x00005000
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(uint16(destPort)),
			},
			//nat dnat ip addr_min reg 1 proto_min reg 2
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				Random:      true,
			},
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictAccept,
			},
		},
	})
	return c, nil
}

func teardownNFTables(c *nftables.Conn, table *nftables.Table) error {
	log.Infoln("tearing down tables")
	c.FlushTable(table)
	ch, err := c.ListChains()

	for _, chain := range ch {
		if chain.Table.Name == "KUBE-VIP" {
			c.DelChain(chain)

		}
	}

	c.Flush()

	return err

}
