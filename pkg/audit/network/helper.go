package network

import (
	"fmt"
	"strings"
)

const (
	TCP                     = 1
	UDP                     = 2
	TCP_STRING              = "TCP"
	UDP_STRING              = "UDP"
	PROTOCOL_UNKNOWN_STRING = "UNKNOWN"
)

// ConvertBytesToIPv4 将字节数组转换为 IPv4 地址字符串
func convertBytesToIPv4(addrBytes [4]byte) string {
	var addrParts []string
	for _, byteVal := range addrBytes {
		addrParts = append(addrParts, fmt.Sprintf("%d", byteVal))
	}
	return strings.Join(addrParts, ".")
}

// ConvertBytesToIPv6 将字节数组转换为 IPv6 地址字符串
func convertBytesToIPv6(addrBytes [16]byte) string {
	var addrParts []string
	var tempPart string
	for idx, byteVal := range addrBytes {
		tempPart += fmt.Sprintf("%02x", byteVal)
		if idx%2 == 1 {
			addrParts = append(addrParts, tempPart)
			tempPart = ""
		}
	}
	return strings.Join(addrParts, ":")
}

// SockTypeToProtocolName 将 socket 类型转换为协议名称
func sockTypeToProtocolName(sockType uint8) string {
	switch sockType {
	case TCP:
		return TCP_STRING
	case UDP:
		return UDP_STRING
	default:
		return PROTOCOL_UNKNOWN_STRING
	}
}
