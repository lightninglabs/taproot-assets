package lncfg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/lightningnetwork/lnd/tor"
)

// TCPResolver is a function signature that resolves an address on a given
// network.
type TCPResolver = func(network, addr string) (*net.TCPAddr, error)

// NormalizeAddresses returns a new slice with all the passed addresses
// normalized with the given default port and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string,
	tcpResolver TCPResolver) ([]net.Addr, error) {

	result := make([]net.Addr, 0, len(addrs))
	seen := map[string]struct{}{}

	for _, addr := range addrs {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, tcpResolver,
		)
		if err != nil {
			return nil, fmt.Errorf("parse address %s failed: %w",
				addr, err)
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}

	return result, nil
}

// EnforceSafeAuthentication enforces "safe" authentication taking into account
// the interfaces that the RPC servers are listening on, and if macaroons and
// TLS is activated or not.
func EnforceSafeAuthentication(addrs []net.Addr, macaroonsActive,
	tlsActive bool) error {

	for _, addr := range addrs {
		if IsLoopback(addr.String()) || IsUnix(addr) || IsPrivate(addr) {
			continue
		}

		if !macaroonsActive {
			return fmt.Errorf("detected RPC server listening on "+
				"publicly reachable interface %v with "+
				"authentication disabled! Refusing to start "+
				"with --no-macaroons specified", addr)
		}

		if !tlsActive {
			return fmt.Errorf("detected RPC server listening on "+
				"publicly reachable interface %v with "+
				"encryption disabled! Refusing to start "+
				"with --no-rest-tls specified", addr)
		}
	}

	return nil
}

func parseNetwork(addr net.Addr) string {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return "tcp4"
		}

		return "tcp6"

	default:
		return addr.Network()
	}
}

// ListenOnAddress creates a listener that listens on the given address.
func ListenOnAddress(addr net.Addr) (net.Listener, error) {
	return net.Listen(parseNetwork(addr), addr.String())
}

// TLSListenOnAddress creates a TLS listener that listens on the given address.
func TLSListenOnAddress(addr net.Addr,
	config *tls.Config) (net.Listener, error) {

	return tls.Listen(parseNetwork(addr), addr.String(), config)
}

// IsLoopback returns true if an address describes a loopback interface.
func IsLoopback(host string) bool {
	if strings.Contains(host, "localhost") {
		return true
	}

	rawHost, _, _ := net.SplitHostPort(host)
	addr := net.ParseIP(rawHost)
	if addr == nil {
		return false
	}

	return addr.IsLoopback()
}

func isIPv6Host(host string) bool {
	v6Addr := net.ParseIP(host)
	if v6Addr == nil {
		return false
	}

	return v6Addr.To4() == nil
}

func isUnspecifiedHost(host string) bool {
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}

	return addr.IsUnspecified()
}

// IsUnix returns true if an address describes an Unix socket address.
func IsUnix(addr net.Addr) bool {
	return strings.HasPrefix(addr.Network(), "unix")
}

// IsPrivate returns true if the address is private.
func IsPrivate(addr net.Addr) bool {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr.IP.IsLinkLocalUnicast() {
			return true
		}

		if addr.IP.IsLinkLocalMulticast() {
			return true
		}

		if ip4 := addr.IP.To4(); ip4 != nil {
			return ip4[0] == 10 ||
				(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
				(ip4[0] == 192 && ip4[1] == 168)
		}

		return len(addr.IP) == net.IPv6len && addr.IP[0]&0xfe == 0xfc

	default:
		return false
	}
}

// ParseAddressString converts an address in string format to a net.Addr.
func ParseAddressString(strAddress string, defaultPort string,
	tcpResolver TCPResolver) (net.Addr, error) {

	var parsedNetwork, parsedAddr string

	if strings.Contains(strAddress, "://") {
		parts := strings.Split(strAddress, "://")
		parsedNetwork, parsedAddr = parts[0], parts[1]
	} else if strings.Contains(strAddress, ":") {
		parts := strings.Split(strAddress, ":")
		parsedNetwork = parts[0]
		parsedAddr = strings.Join(parts[1:], ":")
	}

	switch parsedNetwork {
	case "unix", "unixpacket":
		return net.ResolveUnixAddr(parsedNetwork, parsedAddr)

	case "tcp", "tcp4", "tcp6":
		return tcpResolver(
			parsedNetwork, verifyPort(parsedAddr, defaultPort),
		)

	case "ip", "ip4", "ip6", "udp", "udp4", "udp6", "unixgram":
		return nil, fmt.Errorf("only TCP or unix socket "+
			"addresses are supported: %s", parsedAddr)

	default:
		addrWithPort := verifyPort(strAddress, defaultPort)
		rawHost, rawPort, _ := net.SplitHostPort(addrWithPort)

		if tor.IsOnionHost(rawHost) {
			portNum, err := strconv.Atoi(rawPort)
			if err != nil {
				return nil, err
			}

			return &tor.OnionAddr{
				OnionService: rawHost,
				Port:         portNum,
			}, nil
		}

		if rawHost == "" || IsLoopback(rawHost) ||
			isIPv6Host(rawHost) || isUnspecifiedHost(rawHost) {

			return net.ResolveTCPAddr("tcp", addrWithPort)
		}

		addr, err := tcpResolver("tcp", addrWithPort)
		if err != nil {
			torErrStr := "tor host is unreachable"
			if strings.Contains(err.Error(), torErrStr) {
				return net.ResolveTCPAddr("tcp", addrWithPort)
			}

			return nil, err
		}

		return addr, nil
	}
}

func verifyPort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		if _, err := strconv.Atoi(address); err == nil {
			return net.JoinHostPort("localhost", address)
		}

		if strings.HasPrefix(address, "[") {
			return address + ":" + defaultPort
		}

		return net.JoinHostPort(address, defaultPort)
	}

	if host == "" && port == "" {
		return ":" + defaultPort
	}

	return address
}

// ClientAddressDialer creates a gRPC dialer that can also dial unix socket
// addresses instead of just TCP.
func ClientAddressDialer(defaultPort string) func(context.Context,
	string) (net.Conn, error) {

	return func(ctx context.Context, addr string) (net.Conn, error) {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, net.ResolveTCPAddr,
		)
		if err != nil {
			return nil, err
		}

		d := net.Dialer{}
		return d.DialContext(
			ctx, parsedAddr.Network(), parsedAddr.String(),
		)
	}
}
