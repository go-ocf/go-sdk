package backend_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-ocf/sdk/backend"

	authTest "github.com/go-ocf/cloud/authorization/provider"
	grpcTest "github.com/go-ocf/cloud/grpc-gateway/test"
	kitNetGrpc "github.com/go-ocf/kit/net/grpc"
	"github.com/stretchr/testify/require"
)

func TestObserveDevices(t *testing.T) {
	deviceID := grpcTest.MustFindDeviceByName(grpcTest.TestDeviceName)
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	ctx = kitNetGrpc.CtxWithToken(ctx, authTest.UserToken)

	tearDown := grpcTest.SetUp(ctx, t)
	defer tearDown()

	c := NewTestClient(t)
	defer c.Close(context.Background())
	shutdownDevSim := grpcTest.OnboardDevSim(ctx, t, c.GrpcGatewayClient(), deviceID, grpcTest.GW_HOST, grpcTest.GetAllBackendResourceLinks())

	h := makeTestDevicesObservationHandler()
	id, err := c.ObserveDevices(ctx, h)
	require.NoError(t, err)
	defer func() {
		c.StopObservingDevices(ctx, id)
	}()

	res := <-h.res
	require.Equal(t, backend.DevicesObservationEvent{
		DeviceID: deviceID,
		Event:    backend.DevicesObservationEvent_REGISTERED,
	}, res)
	res = <-h.res
	require.Equal(t, backend.DevicesObservationEvent{
		DeviceID: deviceID,
		Event:    backend.DevicesObservationEvent_ONLINE,
	}, res)

	shutdownDevSim()
	res = <-h.res
	require.Equal(t, backend.DevicesObservationEvent{
		DeviceID: deviceID,
		Event:    backend.DevicesObservationEvent_OFFLINE,
	}, res)
}

func makeTestDevicesObservationHandler() *testDevicesObservationHandler {
	return &testDevicesObservationHandler{res: make(chan backend.DevicesObservationEvent, 10)}
}

type testDevicesObservationHandler struct {
	res chan backend.DevicesObservationEvent
}

func (h *testDevicesObservationHandler) Handle(ctx context.Context, body backend.DevicesObservationEvent) error {
	h.res <- body
	return nil
}

func (h *testDevicesObservationHandler) Error(err error) { fmt.Println(err) }

func (h *testDevicesObservationHandler) OnClose() { fmt.Println("devices observation was closed") }
