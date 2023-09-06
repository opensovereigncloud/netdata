// Copyright 2023 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	k8sClient         client.Client
	netdataReconciler *NetdataReconciler
)

func TestAPIs(t *testing.T) {
	SetDefaultConsistentlyPollingInterval(200 * time.Millisecond)
	SetDefaultEventuallyPollingInterval(200 * time.Millisecond)
	SetDefaultConsistentlyDuration(3 * time.Second)
	SetDefaultEventuallyTimeout(7 * time.Second)
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controllers")
}

var _ = BeforeSuite(func() {
	path, err := exec.Command("go", "run", "sigs.k8s.io/controller-runtime/tools/setup-envtest", "use", "-p=path").Output()
	Expect(err).NotTo(HaveOccurred())
	Expect(os.Setenv("KUBEBUILDER_ASSETS", string(path))).To(Succeed())

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)
	l := logr.FromContextOrDiscard(ctx)
	klog.SetLogger(l)
	//ctrl.SetLogger(l)

	scheme := runtime.NewScheme()
	Expect(kscheme.AddToScheme(scheme)).To(Succeed())
	Expect(ipamv1alpha1.AddToScheme(scheme)).To(Succeed())
	//+kubebuilder:scaffold:scheme

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "test", "ipam.onmetal.de_subnets.yaml")},
		ErrorIfCRDPathMissing: true,
	}
	var cfg *rest.Config
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())
	DeferCleanup(testEnv.Stop)

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	var mgr manager.Manager

	mgr, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(mgr).NotTo(BeNil())

	netdataReconciler = &NetdataReconciler{
		Client: mgr.GetClient(),
		Log:    mgr.GetLogger(),
		Config: "../config/default/netdata-config.yaml"}

	Expect(netdataReconciler.SetupWithManager(mgr)).To(Succeed())

	mgrCtx, mgrCancel := context.WithCancel(ctx)
	var mgrDone sync.WaitGroup
	mgrDone.Add(1)
	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(mgrCtx)).To(Succeed())
		mgrDone.Done()
	}()
	DeferCleanup(func() {
		mgrCancel()
		mgrDone.Wait()
	})
	time.Sleep(time.Second)
})
