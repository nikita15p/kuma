// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.14.0
// source: pkg/config/app/kumactl/v1alpha1/config.proto

package v1alpha1

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
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

// Configuration defines configuration of `kumactl`.
type Configuration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// List of known Control Planes.
	ControlPlanes []*ControlPlane `protobuf:"bytes,1,rep,name=control_planes,json=controlPlanes,proto3" json:"control_planes,omitempty"`
	// List of configured `kumactl` contexts.
	Contexts []*Context `protobuf:"bytes,2,rep,name=contexts,proto3" json:"contexts,omitempty"`
	// Name of the context to use by default.
	CurrentContext string `protobuf:"bytes,3,opt,name=current_context,json=currentContext,proto3" json:"current_context,omitempty"`
}

func (x *Configuration) Reset() {
	*x = Configuration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Configuration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Configuration) ProtoMessage() {}

func (x *Configuration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Configuration.ProtoReflect.Descriptor instead.
func (*Configuration) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{0}
}

func (x *Configuration) GetControlPlanes() []*ControlPlane {
	if x != nil {
		return x.ControlPlanes
	}
	return nil
}

func (x *Configuration) GetContexts() []*Context {
	if x != nil {
		return x.Contexts
	}
	return nil
}

func (x *Configuration) GetCurrentContext() string {
	if x != nil {
		return x.CurrentContext
	}
	return ""
}

// ControlPlane defines a Control Plane.
type ControlPlane struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name defines a reference name for a given Control Plane.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Coordinates defines coordinates of a given Control Plane.
	Coordinates *ControlPlaneCoordinates `protobuf:"bytes,2,opt,name=coordinates,proto3" json:"coordinates,omitempty"`
}

func (x *ControlPlane) Reset() {
	*x = ControlPlane{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ControlPlane) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ControlPlane) ProtoMessage() {}

func (x *ControlPlane) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ControlPlane.ProtoReflect.Descriptor instead.
func (*ControlPlane) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{1}
}

func (x *ControlPlane) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ControlPlane) GetCoordinates() *ControlPlaneCoordinates {
	if x != nil {
		return x.Coordinates
	}
	return nil
}

// ControlPlaneCoordinates defines coordinates of a Control Plane.
type ControlPlaneCoordinates struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ApiServer *ControlPlaneCoordinates_ApiServer `protobuf:"bytes,1,opt,name=api_server,json=apiServer,proto3" json:"api_server,omitempty"`
}

func (x *ControlPlaneCoordinates) Reset() {
	*x = ControlPlaneCoordinates{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ControlPlaneCoordinates) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ControlPlaneCoordinates) ProtoMessage() {}

func (x *ControlPlaneCoordinates) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ControlPlaneCoordinates.ProtoReflect.Descriptor instead.
func (*ControlPlaneCoordinates) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{2}
}

func (x *ControlPlaneCoordinates) GetApiServer() *ControlPlaneCoordinates_ApiServer {
	if x != nil {
		return x.ApiServer
	}
	return nil
}

// Context defines a context in which individual `kumactl` commands run.
type Context struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name defines a reference name for a given context.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// ControlPlane defines a reference to a known Control Plane.
	ControlPlane string `protobuf:"bytes,2,opt,name=control_plane,json=controlPlane,proto3" json:"control_plane,omitempty"`
	// Defaults defines default settings for a given context.
	Defaults *Context_Defaults `protobuf:"bytes,3,opt,name=defaults,proto3" json:"defaults,omitempty"`
}

func (x *Context) Reset() {
	*x = Context{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Context) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Context) ProtoMessage() {}

func (x *Context) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Context.ProtoReflect.Descriptor instead.
func (*Context) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{3}
}

func (x *Context) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Context) GetControlPlane() string {
	if x != nil {
		return x.ControlPlane
	}
	return ""
}

func (x *Context) GetDefaults() *Context_Defaults {
	if x != nil {
		return x.Defaults
	}
	return nil
}

type ControlPlaneCoordinates_Headers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *ControlPlaneCoordinates_Headers) Reset() {
	*x = ControlPlaneCoordinates_Headers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ControlPlaneCoordinates_Headers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ControlPlaneCoordinates_Headers) ProtoMessage() {}

func (x *ControlPlaneCoordinates_Headers) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ControlPlaneCoordinates_Headers.ProtoReflect.Descriptor instead.
func (*ControlPlaneCoordinates_Headers) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{2, 0}
}

func (x *ControlPlaneCoordinates_Headers) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *ControlPlaneCoordinates_Headers) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

type ControlPlaneCoordinates_ApiServer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

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
	ClientKeyFile string `protobuf:"bytes,4,opt,name=client_key_file,json=clientKeyFile,proto3" json:"client_key_file,omitempty"`
	// Headers to be added for communication with Kuma control plane
	Headers []*ControlPlaneCoordinates_Headers `protobuf:"bytes,5,rep,name=headers,proto3" json:"headers,omitempty"`
}

func (x *ControlPlaneCoordinates_ApiServer) Reset() {
	*x = ControlPlaneCoordinates_ApiServer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ControlPlaneCoordinates_ApiServer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ControlPlaneCoordinates_ApiServer) ProtoMessage() {}

func (x *ControlPlaneCoordinates_ApiServer) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ControlPlaneCoordinates_ApiServer.ProtoReflect.Descriptor instead.
func (*ControlPlaneCoordinates_ApiServer) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{2, 1}
}

func (x *ControlPlaneCoordinates_ApiServer) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *ControlPlaneCoordinates_ApiServer) GetCaCertFile() string {
	if x != nil {
		return x.CaCertFile
	}
	return ""
}

func (x *ControlPlaneCoordinates_ApiServer) GetClientCertFile() string {
	if x != nil {
		return x.ClientCertFile
	}
	return ""
}

func (x *ControlPlaneCoordinates_ApiServer) GetClientKeyFile() string {
	if x != nil {
		return x.ClientKeyFile
	}
	return ""
}

func (x *ControlPlaneCoordinates_ApiServer) GetHeaders() []*ControlPlaneCoordinates_Headers {
	if x != nil {
		return x.Headers
	}
	return nil
}

// Defaults defines default settings for a context.
type Context_Defaults struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Mesh defines a Mesh to use in requests if one is not provided explicitly.
	Mesh string `protobuf:"bytes,1,opt,name=mesh,proto3" json:"mesh,omitempty"`
}

func (x *Context_Defaults) Reset() {
	*x = Context_Defaults{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Context_Defaults) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Context_Defaults) ProtoMessage() {}

func (x *Context_Defaults) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Context_Defaults.ProtoReflect.Descriptor instead.
func (*Context_Defaults) Descriptor() ([]byte, []int) {
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP(), []int{3, 0}
}

func (x *Context_Defaults) GetMesh() string {
	if x != nil {
		return x.Mesh
	}
	return ""
}

var File_pkg_config_app_kumactl_v1alpha1_config_proto protoreflect.FileDescriptor

var file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x70, 0x6b, 0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x70, 0x70,
	0x2f, 0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17,
	0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xc4, 0x01, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x4c, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x6b, 0x75, 0x6d,
	0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e,
	0x65, 0x52, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e, 0x65, 0x73,
	0x12, 0x3c, 0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x78, 0x74, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x73, 0x12, 0x27,
	0x0a, 0x0f, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78,
	0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74,
	0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x22, 0x89, 0x01, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e, 0x65, 0x12, 0x1b, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x5c, 0x0a, 0x0b, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e,
	0x61, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x6b, 0x75, 0x6d,
	0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e,
	0x65, 0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x73, 0x42, 0x08, 0xfa, 0x42,
	0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0b, 0x63, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61,
	0x74, 0x65, 0x73, 0x22, 0xa3, 0x03, 0x0a, 0x17, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50,
	0x6c, 0x61, 0x6e, 0x65, 0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x73, 0x12,
	0x63, 0x0a, 0x0a, 0x61, 0x70, 0x69, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x43, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e, 0x65, 0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x41, 0x70, 0x69, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x42,
	0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x09, 0x61, 0x70, 0x69, 0x53, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x1a, 0x31, 0x0a, 0x07, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0xef, 0x01, 0x0a, 0x09, 0x41, 0x70, 0x69, 0x53,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x72, 0x03, 0x88, 0x01, 0x01, 0x52, 0x03, 0x75, 0x72,
	0x6c, 0x12, 0x20, 0x0a, 0x0c, 0x63, 0x61, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x46,
	0x69, 0x6c, 0x65, 0x12, 0x28, 0x0a, 0x10, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x65,
	0x72, 0x74, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x65, 0x72, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x26, 0x0a,
	0x0f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x69, 0x6c, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x4b, 0x65,
	0x79, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x52, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31,
	0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e, 0x65, 0x43, 0x6f, 0x6f,
	0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x22, 0xbb, 0x01, 0x0a, 0x07, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x1b, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x2c, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02,
	0x10, 0x01, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x50, 0x6c, 0x61, 0x6e, 0x65,
	0x12, 0x45, 0x0a, 0x08, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x29, 0x2e, 0x6b, 0x75, 0x6d, 0x61, 0x63, 0x74, 0x6c, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x78, 0x74, 0x2e, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x73, 0x52, 0x08, 0x64,
	0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x73, 0x1a, 0x1e, 0x0a, 0x08, 0x44, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x65, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6d, 0x65, 0x73, 0x68, 0x42, 0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x75, 0x6d, 0x61, 0x68, 0x71, 0x2f, 0x6b, 0x75, 0x6d,
	0x61, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescOnce sync.Once
	file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescData = file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDesc
)

func file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescGZIP() []byte {
	file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescOnce.Do(func() {
		file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescData)
	})
	return file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDescData
}

var file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_pkg_config_app_kumactl_v1alpha1_config_proto_goTypes = []interface{}{
	(*Configuration)(nil),                     // 0: kumactl.config.v1alpha1.Configuration
	(*ControlPlane)(nil),                      // 1: kumactl.config.v1alpha1.ControlPlane
	(*ControlPlaneCoordinates)(nil),           // 2: kumactl.config.v1alpha1.ControlPlaneCoordinates
	(*Context)(nil),                           // 3: kumactl.config.v1alpha1.Context
	(*ControlPlaneCoordinates_Headers)(nil),   // 4: kumactl.config.v1alpha1.ControlPlaneCoordinates.Headers
	(*ControlPlaneCoordinates_ApiServer)(nil), // 5: kumactl.config.v1alpha1.ControlPlaneCoordinates.ApiServer
	(*Context_Defaults)(nil),                  // 6: kumactl.config.v1alpha1.Context.Defaults
}
var file_pkg_config_app_kumactl_v1alpha1_config_proto_depIdxs = []int32{
	1, // 0: kumactl.config.v1alpha1.Configuration.control_planes:type_name -> kumactl.config.v1alpha1.ControlPlane
	3, // 1: kumactl.config.v1alpha1.Configuration.contexts:type_name -> kumactl.config.v1alpha1.Context
	2, // 2: kumactl.config.v1alpha1.ControlPlane.coordinates:type_name -> kumactl.config.v1alpha1.ControlPlaneCoordinates
	5, // 3: kumactl.config.v1alpha1.ControlPlaneCoordinates.api_server:type_name -> kumactl.config.v1alpha1.ControlPlaneCoordinates.ApiServer
	6, // 4: kumactl.config.v1alpha1.Context.defaults:type_name -> kumactl.config.v1alpha1.Context.Defaults
	4, // 5: kumactl.config.v1alpha1.ControlPlaneCoordinates.ApiServer.headers:type_name -> kumactl.config.v1alpha1.ControlPlaneCoordinates.Headers
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_pkg_config_app_kumactl_v1alpha1_config_proto_init() }
func file_pkg_config_app_kumactl_v1alpha1_config_proto_init() {
	if File_pkg_config_app_kumactl_v1alpha1_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Configuration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ControlPlane); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ControlPlaneCoordinates); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Context); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ControlPlaneCoordinates_Headers); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ControlPlaneCoordinates_ApiServer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Context_Defaults); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_config_app_kumactl_v1alpha1_config_proto_goTypes,
		DependencyIndexes: file_pkg_config_app_kumactl_v1alpha1_config_proto_depIdxs,
		MessageInfos:      file_pkg_config_app_kumactl_v1alpha1_config_proto_msgTypes,
	}.Build()
	File_pkg_config_app_kumactl_v1alpha1_config_proto = out.File
	file_pkg_config_app_kumactl_v1alpha1_config_proto_rawDesc = nil
	file_pkg_config_app_kumactl_v1alpha1_config_proto_goTypes = nil
	file_pkg_config_app_kumactl_v1alpha1_config_proto_depIdxs = nil
}
