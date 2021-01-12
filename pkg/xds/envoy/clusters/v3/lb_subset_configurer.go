package clusters

import (
	envoy_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
)

type LbSubsetConfigurer struct {
	KeySets [][]string
}

var _ ClusterConfigurer = &LbSubsetConfigurer{}

func (e *LbSubsetConfigurer) Configure(c *envoy_cluster.Cluster) error {
	var selectors []*envoy_cluster.Cluster_LbSubsetConfig_LbSubsetSelector
	for _, keys := range e.KeySets {
		if len(keys) == 0 {
			continue
		}
		selectors = append(selectors, &envoy_cluster.Cluster_LbSubsetConfig_LbSubsetSelector{
			Keys: keys,
			// if there is a split by "version", and there is no endpoint with such version we should not fallback to all endpoints of the service
			FallbackPolicy: envoy_cluster.Cluster_LbSubsetConfig_LbSubsetSelector_NO_FALLBACK,
		})
	}
	if len(selectors) > 0 {
		// if lb subset is set, but no label (Kuma's tag) is queried, we should return any endpoint
		c.LbSubsetConfig = &envoy_cluster.Cluster_LbSubsetConfig{
			FallbackPolicy:  envoy_cluster.Cluster_LbSubsetConfig_ANY_ENDPOINT,
			SubsetSelectors: selectors,
		}
	}
	return nil
}
