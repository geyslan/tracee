// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v5.29.0
// source: api/v1beta1/diagnostic.proto

package v1beta1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LogLevel int32

const (
	LogLevel_Debug  LogLevel = 0
	LogLevel_Info   LogLevel = 1
	LogLevel_Warn   LogLevel = 2
	LogLevel_Error  LogLevel = 3
	LogLevel_DPanic LogLevel = 4
	LogLevel_Panic  LogLevel = 5
	LogLevel_Fatal  LogLevel = 6
)

// Enum value maps for LogLevel.
var (
	LogLevel_name = map[int32]string{
		0: "Debug",
		1: "Info",
		2: "Warn",
		3: "Error",
		4: "DPanic",
		5: "Panic",
		6: "Fatal",
	}
	LogLevel_value = map[string]int32{
		"Debug":  0,
		"Info":   1,
		"Warn":   2,
		"Error":  3,
		"DPanic": 4,
		"Panic":  5,
		"Fatal":  6,
	}
)

func (x LogLevel) Enum() *LogLevel {
	p := new(LogLevel)
	*p = x
	return p
}

func (x LogLevel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogLevel) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v1beta1_diagnostic_proto_enumTypes[0].Descriptor()
}

func (LogLevel) Type() protoreflect.EnumType {
	return &file_api_v1beta1_diagnostic_proto_enumTypes[0]
}

func (x LogLevel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogLevel.Descriptor instead.
func (LogLevel) EnumDescriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{0}
}

type GetMetricsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetMetricsRequest) Reset() {
	*x = GetMetricsRequest{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetMetricsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMetricsRequest) ProtoMessage() {}

func (x *GetMetricsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMetricsRequest.ProtoReflect.Descriptor instead.
func (*GetMetricsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{0}
}

type GetMetricsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventCount                 uint64        `protobuf:"varint,1,opt,name=EventCount,proto3" json:"EventCount,omitempty"`
	EventsFiltered             uint64        `protobuf:"varint,2,opt,name=EventsFiltered,proto3" json:"EventsFiltered,omitempty"`
	NetCapCount                uint64        `protobuf:"varint,3,opt,name=NetCapCount,proto3" json:"NetCapCount,omitempty"`
	BPFLogsCount               uint64        `protobuf:"varint,4,opt,name=BPFLogsCount,proto3" json:"BPFLogsCount,omitempty"`
	ErrorCount                 uint64        `protobuf:"varint,5,opt,name=ErrorCount,proto3" json:"ErrorCount,omitempty"`
	LostEvCount                uint64        `protobuf:"varint,6,opt,name=LostEvCount,proto3" json:"LostEvCount,omitempty"`
	LostWrCount                uint64        `protobuf:"varint,7,opt,name=LostWrCount,proto3" json:"LostWrCount,omitempty"`
	LostNtCapCount             uint64        `protobuf:"varint,8,opt,name=LostNtCapCount,proto3" json:"LostNtCapCount,omitempty"`
	LostBPFLogsCount           uint64        `protobuf:"varint,9,opt,name=LostBPFLogsCount,proto3" json:"LostBPFLogsCount,omitempty"`
	BPFPerfEventSubmitAttempts []*EventCount `protobuf:"bytes,10,rep,name=BPFPerfEventSubmitAttempts,proto3" json:"BPFPerfEventSubmitAttempts,omitempty"`
	BPFPerfEventSubmitFailures []*EventCount `protobuf:"bytes,11,rep,name=BPFPerfEventSubmitFailures,proto3" json:"BPFPerfEventSubmitFailures,omitempty"`
}

func (x *GetMetricsResponse) Reset() {
	*x = GetMetricsResponse{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetMetricsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMetricsResponse) ProtoMessage() {}

func (x *GetMetricsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMetricsResponse.ProtoReflect.Descriptor instead.
func (*GetMetricsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{1}
}

func (x *GetMetricsResponse) GetEventCount() uint64 {
	if x != nil {
		return x.EventCount
	}
	return 0
}

func (x *GetMetricsResponse) GetEventsFiltered() uint64 {
	if x != nil {
		return x.EventsFiltered
	}
	return 0
}

func (x *GetMetricsResponse) GetNetCapCount() uint64 {
	if x != nil {
		return x.NetCapCount
	}
	return 0
}

func (x *GetMetricsResponse) GetBPFLogsCount() uint64 {
	if x != nil {
		return x.BPFLogsCount
	}
	return 0
}

func (x *GetMetricsResponse) GetErrorCount() uint64 {
	if x != nil {
		return x.ErrorCount
	}
	return 0
}

func (x *GetMetricsResponse) GetLostEvCount() uint64 {
	if x != nil {
		return x.LostEvCount
	}
	return 0
}

func (x *GetMetricsResponse) GetLostWrCount() uint64 {
	if x != nil {
		return x.LostWrCount
	}
	return 0
}

func (x *GetMetricsResponse) GetLostNtCapCount() uint64 {
	if x != nil {
		return x.LostNtCapCount
	}
	return 0
}

func (x *GetMetricsResponse) GetLostBPFLogsCount() uint64 {
	if x != nil {
		return x.LostBPFLogsCount
	}
	return 0
}

func (x *GetMetricsResponse) GetBPFPerfEventSubmitAttempts() []*EventCount {
	if x != nil {
		return x.BPFPerfEventSubmitAttempts
	}
	return nil
}

func (x *GetMetricsResponse) GetBPFPerfEventSubmitFailures() []*EventCount {
	if x != nil {
		return x.BPFPerfEventSubmitFailures
	}
	return nil
}

type EventCount struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id    EventId `protobuf:"varint,1,opt,name=id,proto3,enum=tracee.v1beta1.EventId" json:"id,omitempty"`
	Count uint64  `protobuf:"varint,2,opt,name=count,proto3" json:"count,omitempty"`
}

func (x *EventCount) Reset() {
	*x = EventCount{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EventCount) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventCount) ProtoMessage() {}

func (x *EventCount) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventCount.ProtoReflect.Descriptor instead.
func (*EventCount) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{2}
}

func (x *EventCount) GetId() EventId {
	if x != nil {
		return x.Id
	}
	return EventId_unspecified
}

func (x *EventCount) GetCount() uint64 {
	if x != nil {
		return x.Count
	}
	return 0
}

type ChangeLogLevelRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Level LogLevel `protobuf:"varint,1,opt,name=level,proto3,enum=tracee.v1beta1.LogLevel" json:"level,omitempty"`
}

func (x *ChangeLogLevelRequest) Reset() {
	*x = ChangeLogLevelRequest{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ChangeLogLevelRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangeLogLevelRequest) ProtoMessage() {}

func (x *ChangeLogLevelRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangeLogLevelRequest.ProtoReflect.Descriptor instead.
func (*ChangeLogLevelRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{3}
}

func (x *ChangeLogLevelRequest) GetLevel() LogLevel {
	if x != nil {
		return x.Level
	}
	return LogLevel_Debug
}

type ChangeLogLevelResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ChangeLogLevelResponse) Reset() {
	*x = ChangeLogLevelResponse{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ChangeLogLevelResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangeLogLevelResponse) ProtoMessage() {}

func (x *ChangeLogLevelResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangeLogLevelResponse.ProtoReflect.Descriptor instead.
func (*ChangeLogLevelResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{4}
}

type GetStacktraceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetStacktraceRequest) Reset() {
	*x = GetStacktraceRequest{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetStacktraceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetStacktraceRequest) ProtoMessage() {}

func (x *GetStacktraceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetStacktraceRequest.ProtoReflect.Descriptor instead.
func (*GetStacktraceRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{5}
}

type GetStacktraceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Stacktrace []byte `protobuf:"bytes,1,opt,name=Stacktrace,proto3" json:"Stacktrace,omitempty"`
}

func (x *GetStacktraceResponse) Reset() {
	*x = GetStacktraceResponse{}
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetStacktraceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetStacktraceResponse) ProtoMessage() {}

func (x *GetStacktraceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_diagnostic_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetStacktraceResponse.ProtoReflect.Descriptor instead.
func (*GetStacktraceResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_diagnostic_proto_rawDescGZIP(), []int{6}
}

func (x *GetStacktraceResponse) GetStacktrace() []byte {
	if x != nil {
		return x.Stacktrace
	}
	return nil
}

var File_api_v1beta1_diagnostic_proto protoreflect.FileDescriptor

var file_api_v1beta1_diagnostic_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x64, 0x69,
	0x61, 0x67, 0x6e, 0x6f, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x17,
	0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x13, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x4d, 0x65,
	0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x92, 0x04, 0x0a,
	0x12, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x46, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x73, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x65, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x4e,
	0x65, 0x74, 0x43, 0x61, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0b, 0x4e, 0x65, 0x74, 0x43, 0x61, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x22, 0x0a,
	0x0c, 0x42, 0x50, 0x46, 0x4c, 0x6f, 0x67, 0x73, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0c, 0x42, 0x50, 0x46, 0x4c, 0x6f, 0x67, 0x73, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4c, 0x6f, 0x73, 0x74, 0x45, 0x76, 0x43, 0x6f, 0x75, 0x6e, 0x74,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x4c, 0x6f, 0x73, 0x74, 0x45, 0x76, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4c, 0x6f, 0x73, 0x74, 0x57, 0x72, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x4c, 0x6f, 0x73, 0x74, 0x57, 0x72,
	0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x4c, 0x6f, 0x73, 0x74, 0x4e, 0x74, 0x43,
	0x61, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x4c,
	0x6f, 0x73, 0x74, 0x4e, 0x74, 0x43, 0x61, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2a, 0x0a,
	0x10, 0x4c, 0x6f, 0x73, 0x74, 0x42, 0x50, 0x46, 0x4c, 0x6f, 0x67, 0x73, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x04, 0x52, 0x10, 0x4c, 0x6f, 0x73, 0x74, 0x42, 0x50, 0x46,
	0x4c, 0x6f, 0x67, 0x73, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x5a, 0x0a, 0x1a, 0x42, 0x50, 0x46,
	0x50, 0x65, 0x72, 0x66, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x41,
	0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x52, 0x1a, 0x42, 0x50, 0x46, 0x50, 0x65,
	0x72, 0x66, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x41, 0x74, 0x74,
	0x65, 0x6d, 0x70, 0x74, 0x73, 0x12, 0x5a, 0x0a, 0x1a, 0x42, 0x50, 0x46, 0x50, 0x65, 0x72, 0x66,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x46, 0x61, 0x69, 0x6c, 0x75,
	0x72, 0x65, 0x73, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x43, 0x6f, 0x75, 0x6e, 0x74, 0x52, 0x1a, 0x42, 0x50, 0x46, 0x50, 0x65, 0x72, 0x66, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65,
	0x73, 0x22, 0x4b, 0x0a, 0x0a, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12,
	0x27, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x49, 0x64, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x47,
	0x0a, 0x15, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c,
	0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x22, 0x18, 0x0a, 0x16, 0x43, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x16, 0x0a, 0x14, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x37, 0x0a, 0x15, 0x47, 0x65, 0x74,
	0x53, 0x74, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x2a, 0x56, 0x0a, 0x08, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x09,
	0x0a, 0x05, 0x44, 0x65, 0x62, 0x75, 0x67, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x49, 0x6e, 0x66,
	0x6f, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x57, 0x61, 0x72, 0x6e, 0x10, 0x02, 0x12, 0x09, 0x0a,
	0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x10, 0x03, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x50, 0x61, 0x6e,
	0x69, 0x63, 0x10, 0x04, 0x12, 0x09, 0x0a, 0x05, 0x50, 0x61, 0x6e, 0x69, 0x63, 0x10, 0x05, 0x12,
	0x09, 0x0a, 0x05, 0x46, 0x61, 0x74, 0x61, 0x6c, 0x10, 0x06, 0x32, 0xa7, 0x02, 0x0a, 0x11, 0x44,
	0x69, 0x61, 0x67, 0x6e, 0x6f, 0x73, 0x74, 0x69, 0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x53, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x21,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x22, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5f, 0x0a, 0x0e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4c,
	0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x25, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65,
	0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4c,
	0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5c, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61,
	0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x12, 0x24, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65,
	0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x63,
	0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x2f, 0x61, 0x71, 0x75, 0x61, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_v1beta1_diagnostic_proto_rawDescOnce sync.Once
	file_api_v1beta1_diagnostic_proto_rawDescData = file_api_v1beta1_diagnostic_proto_rawDesc
)

func file_api_v1beta1_diagnostic_proto_rawDescGZIP() []byte {
	file_api_v1beta1_diagnostic_proto_rawDescOnce.Do(func() {
		file_api_v1beta1_diagnostic_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1beta1_diagnostic_proto_rawDescData)
	})
	return file_api_v1beta1_diagnostic_proto_rawDescData
}

var file_api_v1beta1_diagnostic_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_v1beta1_diagnostic_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_api_v1beta1_diagnostic_proto_goTypes = []any{
	(LogLevel)(0),                  // 0: tracee.v1beta1.LogLevel
	(*GetMetricsRequest)(nil),      // 1: tracee.v1beta1.GetMetricsRequest
	(*GetMetricsResponse)(nil),     // 2: tracee.v1beta1.GetMetricsResponse
	(*EventCount)(nil),             // 3: tracee.v1beta1.EventCount
	(*ChangeLogLevelRequest)(nil),  // 4: tracee.v1beta1.ChangeLogLevelRequest
	(*ChangeLogLevelResponse)(nil), // 5: tracee.v1beta1.ChangeLogLevelResponse
	(*GetStacktraceRequest)(nil),   // 6: tracee.v1beta1.GetStacktraceRequest
	(*GetStacktraceResponse)(nil),  // 7: tracee.v1beta1.GetStacktraceResponse
	(EventId)(0),                   // 8: tracee.v1beta1.EventId
}
var file_api_v1beta1_diagnostic_proto_depIdxs = []int32{
	3, // 0: tracee.v1beta1.GetMetricsResponse.BPFPerfEventSubmitAttempts:type_name -> tracee.v1beta1.EventCount
	3, // 1: tracee.v1beta1.GetMetricsResponse.BPFPerfEventSubmitFailures:type_name -> tracee.v1beta1.EventCount
	8, // 2: tracee.v1beta1.EventCount.id:type_name -> tracee.v1beta1.EventId
	0, // 3: tracee.v1beta1.ChangeLogLevelRequest.level:type_name -> tracee.v1beta1.LogLevel
	1, // 4: tracee.v1beta1.DiagnosticService.GetMetrics:input_type -> tracee.v1beta1.GetMetricsRequest
	4, // 5: tracee.v1beta1.DiagnosticService.ChangeLogLevel:input_type -> tracee.v1beta1.ChangeLogLevelRequest
	6, // 6: tracee.v1beta1.DiagnosticService.GetStacktrace:input_type -> tracee.v1beta1.GetStacktraceRequest
	2, // 7: tracee.v1beta1.DiagnosticService.GetMetrics:output_type -> tracee.v1beta1.GetMetricsResponse
	5, // 8: tracee.v1beta1.DiagnosticService.ChangeLogLevel:output_type -> tracee.v1beta1.ChangeLogLevelResponse
	7, // 9: tracee.v1beta1.DiagnosticService.GetStacktrace:output_type -> tracee.v1beta1.GetStacktraceResponse
	7, // [7:10] is the sub-list for method output_type
	4, // [4:7] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_api_v1beta1_diagnostic_proto_init() }
func file_api_v1beta1_diagnostic_proto_init() {
	if File_api_v1beta1_diagnostic_proto != nil {
		return
	}
	file_api_v1beta1_event_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_v1beta1_diagnostic_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1beta1_diagnostic_proto_goTypes,
		DependencyIndexes: file_api_v1beta1_diagnostic_proto_depIdxs,
		EnumInfos:         file_api_v1beta1_diagnostic_proto_enumTypes,
		MessageInfos:      file_api_v1beta1_diagnostic_proto_msgTypes,
	}.Build()
	File_api_v1beta1_diagnostic_proto = out.File
	file_api_v1beta1_diagnostic_proto_rawDesc = nil
	file_api_v1beta1_diagnostic_proto_goTypes = nil
	file_api_v1beta1_diagnostic_proto_depIdxs = nil
}
