// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"

	"github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
	"github.com/ironcore-dev/netdata/controllers"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	// +kubebuilder:scaffold:scheme

	if err := v1alpha1.AddToScheme(scheme); err != nil {
		_ = errors.Wrap(err, "unable to add registered types to client scheme")
	}
}

func getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func main() {
	debugMode, _ := strconv.ParseBool(getenv("DEBUG", "FALSE"))
	ctrl.SetLogger(zap.New(zap.UseDevMode(debugMode)))
	controllers.Start()
}
