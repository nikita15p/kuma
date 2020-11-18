package modifications

import (
	envoy_api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	envoy_route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	envoy_hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v2"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"

	mesh_proto "github.com/kumahq/kuma/api/mesh/v1alpha1"
	core_xds "github.com/kumahq/kuma/pkg/core/xds"
	util_proto "github.com/kumahq/kuma/pkg/util/proto"
)

// virtualHostModificator assumes that the routes are specified as `routeConfig` in Listeners, not through RDS
// If we ever change it to RDS we need to modify RouteConfiguration objects
type virtualHostModificator mesh_proto.ProxyTemplate_Modifications_VirtualHost

func (c *virtualHostModificator) apply(resources *core_xds.ResourceSet) error {
	virtualHost := &envoy_route.VirtualHost{}
	if err := util_proto.FromYAML([]byte(c.Value), virtualHost); err != nil {
		return err
	}

	for _, resource := range resources.Resources(envoy_resource.ListenerType) {
		listener := resource.Resource.(*envoy_api.Listener)
		if !c.originMatches(resource) {
			continue
		}
		for _, chain := range listener.FilterChains { // apply on all filter chains. We could introduce filter chain matcher as an improvement.
			for _, networkFilter := range chain.Filters {
				if networkFilter.Name == "envoy.filters.network.http_connection_manager" {
					hcm := &envoy_hcm.HttpConnectionManager{}
					err := ptypes.UnmarshalAny(networkFilter.ConfigType.(*envoy_listener.Filter_TypedConfig).TypedConfig, hcm)
					if err != nil {
						return err
					}
					if err := c.applyHCMModification(hcm, virtualHost); err != nil {
						return err
					}
					any, err := util_proto.MarshalAnyDeterministic(hcm)
					if err != nil {
						return err
					}
					networkFilter.ConfigType.(*envoy_listener.Filter_TypedConfig).TypedConfig = any
				}
			}
		}
	}
	return nil
}

func (c *virtualHostModificator) applyHCMModification(hcm *envoy_hcm.HttpConnectionManager, virtualHost *envoy_route.VirtualHost) error {
	routeCfg := hcm.GetRouteConfig()
	if routeCfg == nil {
		return nil // ignore HCMs without embedded routes
	}
	if !c.routeConfigurationMatches(routeCfg) {
		return nil
	}
	switch c.Operation {
	case mesh_proto.OpAdd:
		c.add(routeCfg, virtualHost)
	case mesh_proto.OpRemove:
		c.remove(routeCfg)
	case mesh_proto.OpPatch:
		c.patch(routeCfg, virtualHost)
	default:
		return errors.Errorf("invalid operation: %s", c.Operation)
	}
	return nil
}

func (c *virtualHostModificator) patch(routeCfg *envoy_api.RouteConfiguration, vHostPatch *envoy_route.VirtualHost) {
	for _, vHost := range routeCfg.VirtualHosts {
		if c.virtualHostMatches(vHost) {
			proto.Merge(vHost, vHostPatch)
		}
	}
}

func (c *virtualHostModificator) remove(routeCfg *envoy_api.RouteConfiguration) {
	var vHosts []*envoy_route.VirtualHost
	for _, vHost := range routeCfg.VirtualHosts {
		if !c.virtualHostMatches(vHost) {
			vHosts = append(vHosts, vHost)
		}
	}
	routeCfg.VirtualHosts = vHosts
}

func (c *virtualHostModificator) add(routeCfg *envoy_api.RouteConfiguration, vHost *envoy_route.VirtualHost) {
	routeCfg.VirtualHosts = append(routeCfg.VirtualHosts, vHost)
}

func (c *virtualHostModificator) virtualHostMatches(vHost *envoy_route.VirtualHost) bool {
	if c.Match.GetName() != "" && c.Match.GetName() != vHost.Name {
		return false
	}
	return true
}

func (c *virtualHostModificator) originMatches(routeCfg *core_xds.Resource) bool {
	return c.Match.GetOrigin() == "" || (c.Match.GetOrigin() == routeCfg.Origin)
}

func (c *virtualHostModificator) routeConfigurationMatches(routeCfg *envoy_api.RouteConfiguration) bool {
	if c.Match.GetRouteConfigurationName() != "" && c.Match.GetRouteConfigurationName() != routeCfg.Name {
		return false
	}
	return true
}
