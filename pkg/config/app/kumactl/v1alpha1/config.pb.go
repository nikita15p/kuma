// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pkg/config/app/kumactl/v1alpha1/config.proto

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

// Configuration defines configuration of `kumactl`.
type Configuration struct {
	// List of known Control Planes.
	ControlPlanes []*ControlPlane `protobuf:"bytes,1,rep,name=control_planes,json=controlPlanes,proto3" json:"control_planes,omitempty"`
	// List of configured `kumactl` contexts.
	Contexts []*Context `protobuf:"bytes,2,rep,name=contexts,proto3" json:"contexts,omitempty"`
	// Name of the context to use by default.
	CurrentContext       string   `protobuf:"bytes,3,opt,name=current_context,json=currentContext,proto3" json:"current_context,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Configuration) Reset()         { *m = Configuration{} }
func (m *Configuration) String() string { return proto.CompactTextString(m) }
func (*Configuration) ProtoMessage()    {}
func (*Configuration) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{0}
}

func (m *Configuration) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Configuration.Unmarshal(m, b)
}
func (m *Configuration) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Configuration.Marshal(b, m, deterministic)
}
func (m *Configuration) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Configuration.Merge(m, src)
}
func (m *Configuration) XXX_Size() int {
	return xxx_messageInfo_Configuration.Size(m)
}
func (m *Configuration) XXX_DiscardUnknown() {
	xxx_messageInfo_Configuration.DiscardUnknown(m)
}

var xxx_messageInfo_Configuration proto.InternalMessageInfo

func (m *Configuration) GetControlPlanes() []*ControlPlane {
	if m != nil {
		return m.ControlPlanes
	}
	return nil
}

func (m *Configuration) GetContexts() []*Context {
	if m != nil {
		return m.Contexts
	}
	return nil
}

func (m *Configuration) GetCurrentContext() string {
	if m != nil {
		return m.CurrentContext
	}
	return ""
}

// ControlPlane defines a Control Plane.
type ControlPlane struct {
	// Name defines a reference name for a given Control Plane.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Coordinates defines coordinates of a given Control Plane.
	Coordinates          *ControlPlaneCoordinates `protobuf:"bytes,2,opt,name=coordinates,proto3" json:"coordinates,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *ControlPlane) Reset()         { *m = ControlPlane{} }
func (m *ControlPlane) String() string { return proto.CompactTextString(m) }
func (*ControlPlane) ProtoMessage()    {}
func (*ControlPlane) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{1}
}

func (m *ControlPlane) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ControlPlane.Unmarshal(m, b)
}
func (m *ControlPlane) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ControlPlane.Marshal(b, m, deterministic)
}
func (m *ControlPlane) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ControlPlane.Merge(m, src)
}
func (m *ControlPlane) XXX_Size() int {
	return xxx_messageInfo_ControlPlane.Size(m)
}
func (m *ControlPlane) XXX_DiscardUnknown() {
	xxx_messageInfo_ControlPlane.DiscardUnknown(m)
}

var xxx_messageInfo_ControlPlane proto.InternalMessageInfo

func (m *ControlPlane) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ControlPlane) GetCoordinates() *ControlPlaneCoordinates {
	if m != nil {
		return m.Coordinates
	}
	return nil
}

// ControlPlaneCoordinates defines coordinates of a Control Plane.
type ControlPlaneCoordinates struct {
	ApiServer            *ControlPlaneCoordinates_ApiServer `protobuf:"bytes,1,opt,name=api_server,json=apiServer,proto3" json:"api_server,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *ControlPlaneCoordinates) Reset()         { *m = ControlPlaneCoordinates{} }
func (m *ControlPlaneCoordinates) String() string { return proto.CompactTextString(m) }
func (*ControlPlaneCoordinates) ProtoMessage()    {}
func (*ControlPlaneCoordinates) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{2}
}

func (m *ControlPlaneCoordinates) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ControlPlaneCoordinates.Unmarshal(m, b)
}
func (m *ControlPlaneCoordinates) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ControlPlaneCoordinates.Marshal(b, m, deterministic)
}
func (m *ControlPlaneCoordinates) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ControlPlaneCoordinates.Merge(m, src)
}
func (m *ControlPlaneCoordinates) XXX_Size() int {
	return xxx_messageInfo_ControlPlaneCoordinates.Size(m)
}
func (m *ControlPlaneCoordinates) XXX_DiscardUnknown() {
	xxx_messageInfo_ControlPlaneCoordinates.DiscardUnknown(m)
}

var xxx_messageInfo_ControlPlaneCoordinates proto.InternalMessageInfo

func (m *ControlPlaneCoordinates) GetApiServer() *ControlPlaneCoordinates_ApiServer {
	if m != nil {
		return m.ApiServer
	}
	return nil
}

type ControlPlaneCoordinates_ApiServer struct {
	// URL defines URL of the Control Plane API Server.
	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	// CaCert defines the certificate authority which will be used to verify
	// connection to the control plane API server
	CaCertFile string `protobuf:"bytes,2,opt,name=ca_cert_file,json=caCertFile,proto3" json:"ca_cert_file,omitempty"`
	// ClientCert defines the certificate of the authorized client of the
	// control plane API server
	ClientCertFile string `protobuf:"bytes,3,opt,name=client_cert_file,json=clientCertFile,proto3" json:"client_cert_file,omitempty"`
	// ClientKey defines the key of the authorized client of the control plane
	// API server
	ClientKeyFile        string   `protobuf:"bytes,4,opt,name=client_key_file,json=clientKeyFile,proto3" json:"client_key_file,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ControlPlaneCoordinates_ApiServer) Reset()         { *m = ControlPlaneCoordinates_ApiServer{} }
func (m *ControlPlaneCoordinates_ApiServer) String() string { return proto.CompactTextString(m) }
func (*ControlPlaneCoordinates_ApiServer) ProtoMessage()    {}
func (*ControlPlaneCoordinates_ApiServer) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{2, 0}
}

func (m *ControlPlaneCoordinates_ApiServer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ControlPlaneCoordinates_ApiServer.Unmarshal(m, b)
}
func (m *ControlPlaneCoordinates_ApiServer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ControlPlaneCoordinates_ApiServer.Marshal(b, m, deterministic)
}
func (m *ControlPlaneCoordinates_ApiServer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ControlPlaneCoordinates_ApiServer.Merge(m, src)
}
func (m *ControlPlaneCoordinates_ApiServer) XXX_Size() int {
	return xxx_messageInfo_ControlPlaneCoordinates_ApiServer.Size(m)
}
func (m *ControlPlaneCoordinates_ApiServer) XXX_DiscardUnknown() {
	xxx_messageInfo_ControlPlaneCoordinates_ApiServer.DiscardUnknown(m)
}

var xxx_messageInfo_ControlPlaneCoordinates_ApiServer proto.InternalMessageInfo

func (m *ControlPlaneCoordinates_ApiServer) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *ControlPlaneCoordinates_ApiServer) GetCaCertFile() string {
	if m != nil {
		return m.CaCertFile
	}
	return ""
}

func (m *ControlPlaneCoordinates_ApiServer) GetClientCertFile() string {
	if m != nil {
		return m.ClientCertFile
	}
	return ""
}

func (m *ControlPlaneCoordinates_ApiServer) GetClientKeyFile() string {
	if m != nil {
		return m.ClientKeyFile
	}
	return ""
}

// Context defines a context in which individual `kumactl` commands run.
type Context struct {
	// Name defines a reference name for a given context.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// ControlPlane defines a reference to a known Control Plane.
	ControlPlane string `protobuf:"bytes,2,opt,name=control_plane,json=controlPlane,proto3" json:"control_plane,omitempty"`
	// Defaults defines default settings for a given context.
	Defaults             *Context_Defaults `protobuf:"bytes,3,opt,name=defaults,proto3" json:"defaults,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Context) Reset()         { *m = Context{} }
func (m *Context) String() string { return proto.CompactTextString(m) }
func (*Context) ProtoMessage()    {}
func (*Context) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{3}
}

func (m *Context) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Context.Unmarshal(m, b)
}
func (m *Context) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Context.Marshal(b, m, deterministic)
}
func (m *Context) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Context.Merge(m, src)
}
func (m *Context) XXX_Size() int {
	return xxx_messageInfo_Context.Size(m)
}
func (m *Context) XXX_DiscardUnknown() {
	xxx_messageInfo_Context.DiscardUnknown(m)
}

var xxx_messageInfo_Context proto.InternalMessageInfo

func (m *Context) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Context) GetControlPlane() string {
	if m != nil {
		return m.ControlPlane
	}
	return ""
}

func (m *Context) GetDefaults() *Context_Defaults {
	if m != nil {
		return m.Defaults
	}
	return nil
}

// Defaults defines default settings for a context.
type Context_Defaults struct {
	// Mesh defines a Mesh to use in requests if one is not provided explicitly.
	Mesh                 string   `protobuf:"bytes,1,opt,name=mesh,proto3" json:"mesh,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Context_Defaults) Reset()         { *m = Context_Defaults{} }
func (m *Context_Defaults) String() string { return proto.CompactTextString(m) }
func (*Context_Defaults) ProtoMessage()    {}
func (*Context_Defaults) Descriptor() ([]byte, []int) {
	return fileDescriptor_18c2b02c7dd453f4, []int{3, 0}
}

func (m *Context_Defaults) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Context_Defaults.Unmarshal(m, b)
}
func (m *Context_Defaults) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Context_Defaults.Marshal(b, m, deterministic)
}
func (m *Context_Defaults) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Context_Defaults.Merge(m, src)
}
func (m *Context_Defaults) XXX_Size() int {
	return xxx_messageInfo_Context_Defaults.Size(m)
}
func (m *Context_Defaults) XXX_DiscardUnknown() {
	xxx_messageInfo_Context_Defaults.DiscardUnknown(m)
}

var xxx_messageInfo_Context_Defaults proto.InternalMessageInfo

func (m *Context_Defaults) GetMesh() string {
	if m != nil {
		return m.Mesh
	}
	return ""
}

func init() {
	proto.RegisterType((*Configuration)(nil), "kumactl.config.v1alpha1.Configuration")
	proto.RegisterType((*ControlPlane)(nil), "kumactl.config.v1alpha1.ControlPlane")
	proto.RegisterType((*ControlPlaneCoordinates)(nil), "kumactl.config.v1alpha1.ControlPlaneCoordinates")
	proto.RegisterType((*ControlPlaneCoordinates_ApiServer)(nil), "kumactl.config.v1alpha1.ControlPlaneCoordinates.ApiServer")
	proto.RegisterType((*Context)(nil), "kumactl.config.v1alpha1.Context")
	proto.RegisterType((*Context_Defaults)(nil), "kumactl.config.v1alpha1.Context.Defaults")
}

func init() {
	proto.RegisterFile("pkg/config/app/kumactl/v1alpha1/config.proto", fileDescriptor_18c2b02c7dd453f4)
}

var fileDescriptor_18c2b02c7dd453f4 = []byte{
	// 455 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xc1, 0x6e, 0xd3, 0x30,
	0x1c, 0xc6, 0xe5, 0xb6, 0xb0, 0xf4, 0x9f, 0x76, 0x9b, 0x7c, 0x69, 0x55, 0x24, 0x54, 0x55, 0x02,
	0x8a, 0x34, 0x25, 0xac, 0xdc, 0x10, 0x17, 0x12, 0xe0, 0x02, 0x07, 0x14, 0x6e, 0x08, 0x29, 0x32,
	0xee, 0xbf, 0x9b, 0x55, 0x37, 0x89, 0x1c, 0xa7, 0xda, 0xde, 0x00, 0x78, 0x05, 0x78, 0x13, 0xae,
	0x3c, 0xd5, 0x4e, 0xc8, 0x8e, 0x93, 0x85, 0xc3, 0x06, 0xbb, 0x39, 0x9f, 0x7f, 0xdf, 0x97, 0x2f,
	0xfe, 0x3b, 0x70, 0x52, 0x6c, 0xcf, 0x42, 0x9e, 0x67, 0x1b, 0x71, 0x16, 0xb2, 0xa2, 0x08, 0xb7,
	0xd5, 0x8e, 0x71, 0x2d, 0xc3, 0xfd, 0x29, 0x93, 0xc5, 0x39, 0x3b, 0x75, 0x7b, 0x41, 0xa1, 0x72,
	0x9d, 0xd3, 0x89, 0xdb, 0x0e, 0x9c, 0xda, 0x50, 0xb3, 0xc9, 0x9e, 0x49, 0xb1, 0x66, 0x1a, 0xc3,
	0x66, 0x51, 0x3b, 0x16, 0xbf, 0x09, 0x8c, 0x63, 0x0b, 0x57, 0x8a, 0x69, 0x91, 0x67, 0xf4, 0x3d,
	0x1c, 0xf2, 0x3c, 0xd3, 0x2a, 0x97, 0x69, 0x21, 0x59, 0x86, 0xe5, 0x94, 0xcc, 0xfb, 0x4b, 0x7f,
	0xf5, 0x28, 0xb8, 0x21, 0x3c, 0x88, 0x6b, 0xfc, 0x83, 0xa1, 0x93, 0x31, 0xef, 0x3c, 0x95, 0xf4,
	0x25, 0x78, 0x46, 0xc0, 0x0b, 0x5d, 0x4e, 0x7b, 0x36, 0x67, 0x7e, 0x6b, 0x0e, 0x5e, 0xe8, 0xa4,
	0x75, 0xd0, 0x27, 0x70, 0xc4, 0x2b, 0xa5, 0x30, 0xd3, 0xa9, 0xd3, 0xa6, 0xfd, 0x39, 0x59, 0x0e,
	0x93, 0x43, 0x27, 0x3b, 0xcb, 0xe2, 0x1b, 0x81, 0x51, 0xb7, 0x06, 0x7d, 0x00, 0x83, 0x8c, 0xed,
	0x70, 0x4a, 0x0c, 0x1e, 0x1d, 0x5c, 0x45, 0x03, 0xd5, 0x3b, 0x26, 0x89, 0x15, 0xe9, 0x67, 0xf0,
	0x79, 0x9e, 0xab, 0xb5, 0xc8, 0x98, 0x46, 0xd3, 0x8b, 0x2c, 0xfd, 0xd5, 0xb3, 0xff, 0xfa, 0xbe,
	0xf8, 0xda, 0x17, 0x79, 0x57, 0xd1, 0xbd, 0xef, 0xc4, 0xc4, 0x76, 0xe3, 0x16, 0x3f, 0x7b, 0x30,
	0xb9, 0xc1, 0x42, 0x39, 0x00, 0x2b, 0x44, 0x5a, 0xa2, 0xda, 0xa3, 0xb2, 0xe5, 0xfc, 0xd5, 0x8b,
	0xbb, 0xbe, 0x38, 0x78, 0x55, 0x88, 0x8f, 0x36, 0xa1, 0x53, 0x61, 0xc8, 0x1a, 0x71, 0xf6, 0x83,
	0xc0, 0xb0, 0x45, 0xe8, 0x0c, 0xfa, 0x95, 0x92, 0xee, 0x20, 0x0c, 0xaf, 0xfa, 0x5f, 0x09, 0x49,
	0x8c, 0x48, 0xe7, 0x30, 0xe2, 0x2c, 0xe5, 0xa8, 0x74, 0xba, 0x11, 0x12, 0xed, 0x49, 0x0c, 0x13,
	0xe0, 0x2c, 0x46, 0xa5, 0xdf, 0x0a, 0x89, 0x74, 0x09, 0xc7, 0x5c, 0x0a, 0x3b, 0x80, 0x96, 0x6a,
	0x46, 0x60, 0xf5, 0x96, 0x7c, 0x0c, 0x47, 0x8e, 0xdc, 0xe2, 0x65, 0x0d, 0x0e, 0x2c, 0x38, 0xae,
	0xe5, 0x77, 0x78, 0x69, 0xb8, 0xc5, 0x2f, 0x02, 0x07, 0x6e, 0x6c, 0xb7, 0x4f, 0xe9, 0x04, 0xc6,
	0x7f, 0x5d, 0xc4, 0xba, 0xdd, 0x35, 0x35, 0xea, 0xde, 0x34, 0xfa, 0x06, 0xbc, 0x35, 0x6e, 0x58,
	0x25, 0x75, 0x69, 0x0b, 0xfa, 0xab, 0xa7, 0xff, 0xba, 0x68, 0xc1, 0x6b, 0x67, 0x48, 0x5a, 0xeb,
	0xec, 0x21, 0x78, 0x8d, 0x4a, 0x29, 0x0c, 0x76, 0x58, 0x9e, 0xd7, 0xed, 0x12, 0xbb, 0x8e, 0xe0,
	0x93, 0xd7, 0xc4, 0x7c, 0xb9, 0x6f, 0x7f, 0xa1, 0xe7, 0x7f, 0x02, 0x00, 0x00, 0xff, 0xff, 0x13,
	0xdb, 0x76, 0x8f, 0xa4, 0x03, 0x00, 0x00,
}
