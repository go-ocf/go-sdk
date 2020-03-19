package backend_test

import (
	"context"
	"fmt"
	"testing"

	authTest "github.com/go-ocf/authorization/provider"
	grpcTest "github.com/go-ocf/grpc-gateway/test"
	kitNetCoap "github.com/go-ocf/kit/net/coap"
	kitNetGrpc "github.com/go-ocf/kit/net/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObservingResource(t *testing.T) {
	deviceID := grpcTest.MustFindDeviceByName(grpcTest.TestDeviceName)
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	ctx = kitNetGrpc.CtxWithToken(ctx, authTest.UserToken)

	tearDown := grpcTest.SetUp(ctx, t)
	defer tearDown()

	c := NewTestClient(t)
	defer c.Close(context.Background())
	shutdownDevSim := grpcTest.OnboardDevSim(ctx, t, c.GrpcGatewayClient(), deviceID, grpcTest.GW_HOST, grpcTest.GetAllBackendResourceLinks())
	defer shutdownDevSim()

	h := makeTestObservationHandler()
	id, err := c.ObserveResource(ctx, deviceID, "/oc/con", h)
	require.NoError(t, err)
	defer func() {
		err := c.StopObservingResource(ctx, id)
		require.NoError(t, err)
	}()

	name := "observe simulator"
	err = c.UpdateResource(ctx, deviceID, "/oc/con", map[string]interface{}{"n": name}, nil)
	require.NoError(t, err)

	var d OcCon
	res := <-h.res
	err = res(&d)
	require.NoError(t, err)
	assert.Equal(t, grpcTest.TestDeviceName, d.Name)
	res = <-h.res
	err = res(&d)
	require.NoError(t, err)
	require.Equal(t, name, d.Name)

	err = c.UpdateResource(ctx, deviceID, "/oc/con", map[string]interface{}{"n": grpcTest.TestDeviceName}, nil)
	assert.NoError(t, err)
}

func makeTestObservationHandler() *testObservationHandler {
	return &testObservationHandler{res: make(chan kitNetCoap.DecodeFunc, 10)}
}

type OcCon struct {
	Name string `json:"n"`
}

type testObservationHandler struct {
	res chan kitNetCoap.DecodeFunc
}

func (h *testObservationHandler) Handle(ctx context.Context, body kitNetCoap.DecodeFunc) {
	h.res <- body
}

func (h *testObservationHandler) Error(err error) { fmt.Println(err) }

func (h *testObservationHandler) OnClose() { fmt.Println("Observation was closed") }
