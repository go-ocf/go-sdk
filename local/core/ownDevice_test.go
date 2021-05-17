package core_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/plgd-dev/sdk/local/core"
	ocf "github.com/plgd-dev/sdk/local/core"
	"github.com/plgd-dev/sdk/pkg/net/coap"
	"github.com/plgd-dev/sdk/schema"
	"github.com/plgd-dev/sdk/test"
	"github.com/stretchr/testify/require"
)

func TestClient_ownDeviceMfg(t *testing.T) {
	secureDeviceID := test.MustFindDeviceByName(test.TestSecureDeviceName)
	c, err := NewTestSecureClient()
	require.NoError(t, err)
	defer c.Close()
	deviceId := secureDeviceID
	require := require.New(t)
	timeout, cancelTimeout := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelTimeout()

	device, err := c.GetDevice(timeout, ocf.DefaultDiscoveryConfiguration(), deviceId)
	require.NoError(err)
	defer device.Close(timeout)
	eps, err := device.GetEndpoints(timeout)
	require.NoError(err)
	links, err := device.GetResourceLinks(timeout, eps)
	require.NoError(err)

	err = device.Own(timeout, links, c.mfgOtm)
	require.NoError(err)
	err = device.Disown(timeout, links)
	require.NoError(err)

	// try disown second time
	secureDeviceID = test.MustFindDeviceByName(test.TestSecureDeviceName)
	device, err = c.GetDevice(timeout, ocf.DefaultDiscoveryConfiguration(), secureDeviceID)
	require.NoError(err)
	defer device.Close(timeout)
	eps, err = device.GetEndpoints(timeout)
	require.NoError(err)
	links, err = device.GetResourceLinks(timeout, eps)
	require.NoError(err)
	err = device.Disown(timeout, links)
	require.NoError(err)

	secureDeviceID = test.MustFindDeviceByName(test.TestSecureDeviceName)
	device, err = c.GetDevice(timeout, ocf.DefaultDiscoveryConfiguration(), secureDeviceID)
	require.NoError(err)
	eps, err = device.GetEndpoints(timeout)
	require.NoError(err)
	links, err = device.GetResourceLinks(timeout, eps)
	require.NoError(err)
	err = device.Own(timeout, links, c.mfgOtm, core.WithActionDuringOwn(func(ctx context.Context, client *coap.ClientCloseHandler) (string, error) {
		var d schema.Device
		err := client.GetResource(ctx, "/oic/d", &d)
		if err != nil {
			return "", core.MakeInternal(fmt.Errorf("cannot get device resource for owned device(%v): %w", secureDeviceID, err))
		}
		setDeviceOwned := schema.DoxmUpdate{
			DeviceID: d.ProtocolIndependentID,
		}
		/*doxm doesn't send any content for select OTM*/
		err = client.UpdateResource(ctx, schema.DoxmHref, setDeviceOwned, nil)
		if err != nil {
			return "", core.MakeInternal(fmt.Errorf("cannot set device id %v for owned device(%v): %w", d.ProtocolIndependentID, secureDeviceID, err))
		}
		return d.ProtocolIndependentID, nil
	}))
	require.NoError(err)
	require.NotEqual(t, secureDeviceID, device.DeviceID())

	device, err = c.GetDevice(timeout, ocf.DefaultDiscoveryConfiguration(), device.DeviceID())
	require.NoError(err)
	eps, err = device.GetEndpoints(timeout)
	require.NoError(err)
	links, err = device.GetResourceLinks(timeout, eps)
	require.NoError(err)
	err = device.Disown(timeout, links)
	require.NoError(err)
}

func TestClient_ownDeviceJustWorks(t *testing.T) {
	secureDeviceID := test.MustFindDeviceByName(test.TestSecureDeviceName)
	c, err := NewTestSecureClient()
	require.NoError(t, err)
	defer c.Close()
	deviceId := secureDeviceID
	require := require.New(t)
	timeout, cancelTimeout := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelTimeout()

	device, err := c.GetDevice(timeout, ocf.DefaultDiscoveryConfiguration(), deviceId)
	require.NoError(err)
	defer device.Close(timeout)
	eps, err := device.GetEndpoints(timeout)
	require.NoError(err)
	links, err := device.GetResourceLinks(timeout, eps)
	require.NoError(err)

	err = device.Own(timeout, links, c.justWorksOtm)
	require.NoError(err)
	err = device.Disown(timeout, links)
	require.NoError(err)
}
