package tokens

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"

	error_types "github.com/kumahq/kuma/pkg/core/rest/errors/types"
	"github.com/kumahq/kuma/pkg/tokens/builtin/server/types"
	util_http "github.com/kumahq/kuma/pkg/util/http"
)

func NewZoneIngressTokenClient(client util_http.Client) ZoneIngressTokenClient {
	return &httpZoneIngressTokenClient{
		client: client,
	}
}

type ZoneIngressTokenClient interface {
	Generate(zone string) (string, error)
}

type httpZoneIngressTokenClient struct {
	client util_http.Client
}

var _ ZoneIngressTokenClient = &httpZoneIngressTokenClient{}

func (h *httpZoneIngressTokenClient) Generate(zone string) (string, error) {
	tokenReq := &types.ZoneIngressTokenRequest{
		Zone: zone,
	}
	reqBytes, err := json.Marshal(tokenReq)
	if err != nil {
		return "", errors.Wrap(err, "could not marshal token request to json")
	}
	req, err := http.NewRequest("POST", "/tokens/zone-ingress", bytes.NewReader(reqBytes))
	if err != nil {
		return "", errors.Wrap(err, "could not construct the request")
	}
	req.Header.Set("content-type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "could not execute the request")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "could not read a body of the request")
	}
	if resp.StatusCode != 200 {
		kumaErr := error_types.Error{}
		if err := json.Unmarshal(body, &kumaErr); err == nil {
			if kumaErr.Title != "" && kumaErr.Details != "" {
				return "", &kumaErr
			}
		}
		return "", errors.Errorf("(%d): %s", resp.StatusCode, body)
	}
	return string(body), nil
}
