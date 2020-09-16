// Code generated by protoc-gen-go. DO NOT EDIT.
// source: mesh/v1alpha1/externalservice.proto

package v1alpha1

import (
	fmt "fmt"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// ExternalService defines configuration of the externaly accessible service
type ExternalService struct {
	Networking *ExternalService_Networking `protobuf:"bytes,1,opt,name=networking,proto3" json:"networking,omitempty"`
	// Tags associated with the external service,
	// e.g. kuma.io/service=web, kuma.io/protocol, version=1.0.
	Tags                 map[string]string `protobuf:"bytes,5,rep,name=tags,proto3" json:"tags,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *ExternalService) Reset()         { *m = ExternalService{} }
func (m *ExternalService) String() string { return proto.CompactTextString(m) }
func (*ExternalService) ProtoMessage()    {}
func (*ExternalService) Descriptor() ([]byte, []int) {
	return fileDescriptor_df6b95621b774a94, []int{0}
}

func (m *ExternalService) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExternalService.Unmarshal(m, b)
}
func (m *ExternalService) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExternalService.Marshal(b, m, deterministic)
}
func (m *ExternalService) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExternalService.Merge(m, src)
}
func (m *ExternalService) XXX_Size() int {
	return xxx_messageInfo_ExternalService.Size(m)
}
func (m *ExternalService) XXX_DiscardUnknown() {
	xxx_messageInfo_ExternalService.DiscardUnknown(m)
}

var xxx_messageInfo_ExternalService proto.InternalMessageInfo

func (m *ExternalService) GetNetworking() *ExternalService_Networking {
	if m != nil {
		return m.Networking
	}
	return nil
}

func (m *ExternalService) GetTags() map[string]string {
	if m != nil {
		return m.Tags
	}
	return nil
}

// Networking describes the properties of the external service connectivity
type ExternalService_Networking struct {
	// Address of the external service
	Address              string   `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExternalService_Networking) Reset()         { *m = ExternalService_Networking{} }
func (m *ExternalService_Networking) String() string { return proto.CompactTextString(m) }
func (*ExternalService_Networking) ProtoMessage()    {}
func (*ExternalService_Networking) Descriptor() ([]byte, []int) {
	return fileDescriptor_df6b95621b774a94, []int{0, 0}
}

func (m *ExternalService_Networking) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExternalService_Networking.Unmarshal(m, b)
}
func (m *ExternalService_Networking) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExternalService_Networking.Marshal(b, m, deterministic)
}
func (m *ExternalService_Networking) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExternalService_Networking.Merge(m, src)
}
func (m *ExternalService_Networking) XXX_Size() int {
	return xxx_messageInfo_ExternalService_Networking.Size(m)
}
func (m *ExternalService_Networking) XXX_DiscardUnknown() {
	xxx_messageInfo_ExternalService_Networking.DiscardUnknown(m)
}

var xxx_messageInfo_ExternalService_Networking proto.InternalMessageInfo

func (m *ExternalService_Networking) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func init() {
	proto.RegisterType((*ExternalService)(nil), "kuma.mesh.v1alpha1.ExternalService")
	proto.RegisterMapType((map[string]string)(nil), "kuma.mesh.v1alpha1.ExternalService.TagsEntry")
	proto.RegisterType((*ExternalService_Networking)(nil), "kuma.mesh.v1alpha1.ExternalService.Networking")
}

func init() {
	proto.RegisterFile("mesh/v1alpha1/externalservice.proto", fileDescriptor_df6b95621b774a94)
}

var fileDescriptor_df6b95621b774a94 = []byte{
	// 246 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0xce, 0x4d, 0x2d, 0xce,
	0xd0, 0x2f, 0x33, 0x4c, 0xcc, 0x29, 0xc8, 0x48, 0x34, 0xd4, 0x4f, 0xad, 0x28, 0x49, 0x2d, 0xca,
	0x4b, 0xcc, 0x29, 0x4e, 0x2d, 0x2a, 0xcb, 0x4c, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17,
	0x12, 0xca, 0x2e, 0xcd, 0x4d, 0xd4, 0x03, 0xa9, 0xd4, 0x83, 0xa9, 0x94, 0x12, 0x2f, 0x4b, 0xcc,
	0xc9, 0x4c, 0x49, 0x2c, 0x49, 0xd5, 0x87, 0x31, 0x20, 0x8a, 0x95, 0xfa, 0x99, 0xb8, 0xf8, 0x5d,
	0xa1, 0xc6, 0x04, 0x43, 0x8c, 0x11, 0xf2, 0xe3, 0xe2, 0xca, 0x4b, 0x2d, 0x29, 0xcf, 0x2f, 0xca,
	0xce, 0xcc, 0x4b, 0x97, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x36, 0xd2, 0xd3, 0xc3, 0x34, 0x55, 0x0f,
	0x4d, 0xa3, 0x9e, 0x1f, 0x5c, 0x57, 0x10, 0x92, 0x09, 0x42, 0xde, 0x5c, 0x2c, 0x25, 0x89, 0xe9,
	0xc5, 0x12, 0xac, 0x0a, 0xcc, 0x1a, 0xdc, 0x46, 0xba, 0xc4, 0x98, 0x14, 0x92, 0x98, 0x5e, 0xec,
	0x9a, 0x57, 0x52, 0x54, 0xe9, 0xc4, 0xf1, 0xcb, 0x89, 0x75, 0x16, 0x23, 0x13, 0x07, 0x63, 0x10,
	0xd8, 0x10, 0x29, 0x35, 0x2e, 0x2e, 0x84, 0x35, 0x42, 0x12, 0x5c, 0xec, 0x89, 0x29, 0x29, 0x45,
	0xa9, 0xc5, 0xc5, 0x60, 0x77, 0x72, 0x06, 0xc1, 0xb8, 0x52, 0xe6, 0x5c, 0x9c, 0x70, 0x43, 0x84,
	0x04, 0xb8, 0x98, 0xb3, 0x53, 0x2b, 0xa1, 0x4a, 0x40, 0x4c, 0x21, 0x11, 0x2e, 0xd6, 0xb2, 0xc4,
	0x9c, 0xd2, 0x54, 0x09, 0x26, 0xb0, 0x18, 0x84, 0x63, 0xc5, 0x64, 0xc1, 0xe8, 0xc4, 0x15, 0xc5,
	0x01, 0x73, 0x56, 0x12, 0x1b, 0x38, 0x90, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xb4, 0xca,
	0x09, 0x33, 0x78, 0x01, 0x00, 0x00,
}
