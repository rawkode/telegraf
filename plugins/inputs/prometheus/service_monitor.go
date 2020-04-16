package prometheus

import (
	promop "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
)

// ServiceMonitor struct
type ServiceMonitor struct {
	promop.ServiceMonitor
}

// GetMetadata function
func (s *ServiceMonitor) GetMetadata() *metav1.ObjectMeta {
	return metav1.ObjectMeta(s.GetMetadata())
}
