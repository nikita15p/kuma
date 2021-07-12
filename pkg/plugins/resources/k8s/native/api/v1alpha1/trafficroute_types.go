/*
Copyright 2019 Kuma authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kumahq/kuma/pkg/plugins/resources/k8s/native/pkg/model"
)

// TrafficRoute is the Schema for the Traffic Routes API.
//
// +kubebuilder:object:root=true
type TrafficRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Mesh              string `json:"mesh,omitempty"`

	Spec model.RawMessage `json:"spec,omitempty"`
}

// TrafficRouteList contains a list of TrafficRoutes.
//
// +kubebuilder:object:root=true
type TrafficRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrafficRoute{}, &TrafficRouteList{})
}
