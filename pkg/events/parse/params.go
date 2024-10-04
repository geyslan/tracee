package parse

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

func ArgVal[T any](args []trace.Argument, argName string) (T, error) {
	for _, arg := range args {
		if arg.Name == argName {
			val, ok := arg.Value.(T)
			if !ok {
				zeroVal := *new(T)
				return zeroVal, errfmt.Errorf(
					"argument %s is not of type %T, is of type %T",
					argName,
					zeroVal,
					arg.Value,
				)
			}
			return val, nil
		}
	}
	return *new(T), errfmt.Errorf("argument %s not found", argName)
}

func ArgZeroValueFromCType(t string) interface{} {
	switch t {
	case "short":
		return int16(0)
	case "int":
		return int32(0)
	case "long":
		return int64(0)
	case "unsigned short":
		return uint16(0)
	case "unsigned int", "dev_t":
		return uint32(0)
	case "unsigned long":
		return uint64(0)
	case "char*", "const char*", "const char *":
		return string("")
	case "bool":
		return false
	case "float":
		return float32(0)
	case "float64":
		return float64(0)
	case "int8":
		return int8(0)
	case "uint8":
		return uint8(0)
	case "const char**", "const char **":
		return []string{}
	case "trace.ProtoIPv4":
		return trace.ProtoIPv4{}
	case "trace.ProtoIPv6":
		return trace.ProtoIPv6{}
	case "trace.ProtoTCP":
		return trace.ProtoTCP{}
	case "trace.ProtoUDP":
		return trace.ProtoUDP{}
	case "trace.ProtoICMP":
		return trace.ProtoICMP{}
	case "trace.ProtoICMPv6":
		return trace.ProtoICMPv6{}
	case "trace.PktMeta":
		return trace.PktMeta{}
	case "trace.ProtoDNS":
		return trace.ProtoDNS{}
	case "[]trace.DnsQueryData":
		return []trace.DnsQueryData{}
	case "trace.ProtoHTTP":
		return trace.ProtoHTTP{}
	case "trace.ProtoHTTPRequest":
		return trace.ProtoHTTPRequest{}
	case "trace.ProtoHTTPResponse":
		return trace.ProtoHTTPResponse{}
	case "trace.PacketMetadata":
		return trace.PacketMetadata{}
	default:
		return nil
	}
}

// ArgIndex find the index of an argument by name
func ArgIndex(args []trace.Argument, argName string) int {
	for index, arg := range args {
		if arg.Name == argName {
			return index
		}
	}
	return -1
}
