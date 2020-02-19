package privval

import (
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/sm2"
)

func getDialerTestCases(t *testing.T) []dialerTestCase {
	tcpAddr := GetFreeLocalhostAddrPort()
	unixFilePath, err := testUnixAddr()
	require.NoError(t, err)
	unixAddr := fmt.Sprintf("unix://%s", unixFilePath)

	return []dialerTestCase{
		{
			addr:   tcpAddr,
			dialer: DialTCPFn(tcpAddr, testTimeoutReadWrite, sm2.GenPrivKey()),
		},
		{
			addr:   unixAddr,
			dialer: DialUnixFn(unixFilePath),
		},
	}
}

func TestIsConnTimeoutForFundamentalTimeouts(t *testing.T) {
	// Generate a networking timeout
	tcpAddr := GetFreeLocalhostAddrPort()
	dialer := DialTCPFn(tcpAddr, time.Millisecond, sm2.GenPrivKey())
	_, err := dialer()
	assert.Error(t, err)
	assert.True(t, IsConnTimeout(err))
}

func TestIsConnTimeoutForWrappedConnTimeouts(t *testing.T) {
	tcpAddr := GetFreeLocalhostAddrPort()
	dialer := DialTCPFn(tcpAddr, time.Millisecond, sm2.GenPrivKey())
	_, err := dialer()
	assert.Error(t, err)
	err = errors.Wrap(ErrConnectionTimeout, err.Error())
	assert.True(t, IsConnTimeout(err))
}
