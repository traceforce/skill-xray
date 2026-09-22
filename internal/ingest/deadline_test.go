package ingest

// Port of tests/test_url_deadline.py (11 functions, 27 cases): real HTTP parsing
// over an instrumented fake transport with a fake clock; no network, no sleeps.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/traceforce/skill-xray/internal/testutil"
)

var epoch = time.Unix(1_700_000_000, 0)

type chunk struct {
	data  []byte
	delay time.Duration
}

// transfer is the Python `transfer` fixture: a fake clock, the deadline the
// download runs under, every conn handed out and every per-operation timeout the
// transport observed.
type transfer struct {
	clock    time.Duration
	deadline time.Time
	late     bool
	conns    []*fakeConn
	timeouts []time.Duration
}

// wait simulates a socket operation that takes delay under the current
// timeout: the clock advances by min(delay, timeout) and the operation times out
// when delay >= timeout, unless late, when it completes after the whole delay.
func (tr *transfer) wait(delay time.Duration) error {
	timeout := min(urlTimeout, tr.deadline.Sub(now()))
	tr.timeouts = append(tr.timeouts, timeout)
	if tr.late {
		tr.clock += delay
		return nil
	}
	tr.clock += min(delay, timeout)
	if delay >= timeout {
		return os.ErrDeadlineExceeded // a net.Error whose Timeout() is true
	}
	return nil
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake" }

// fakeConn serves scripted response chunks; a delayed chunk arrives one byte per
// read and a delayed request is sent one byte per write, as the Python Wire does.
type fakeConn struct {
	tr        *transfer
	chunks    []chunk
	sendDelay time.Duration
	closed    bool
}

func (c *fakeConn) wait(d time.Duration) error {
	if c.tr == nil {
		return nil
	}
	return c.tr.wait(d)
}

func (c *fakeConn) Read(b []byte) (int, error) {
	for len(c.chunks) > 0 && len(c.chunks[0].data) == 0 {
		c.chunks = c.chunks[1:]
	}
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	ch := &c.chunks[0]
	if err := c.wait(ch.delay); err != nil {
		return 0, err
	}
	n := len(ch.data)
	if ch.delay > 0 {
		n = 1
	}
	n = min(n, len(b))
	copy(b, ch.data[:n])
	ch.data = ch.data[n:]
	return n, nil
}

func (c *fakeConn) Write(b []byte) (int, error) {
	step := len(b)
	if c.sendDelay > 0 {
		step = 1
	}
	for i := 0; i < len(b); i += step {
		if err := c.wait(c.sendDelay); err != nil {
			return i, err
		}
	}
	return len(b), nil
}

func (c *fakeConn) Close() error                     { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type delays struct{ connect, handshake, send time.Duration }

func setupTransfer(t *testing.T, parts []chunk, d delays, late bool) *transfer {
	tr := &transfer{late: late}
	testutil.Swap(t, &now, func() time.Time { return epoch.Add(tr.clock) })
	testutil.Swap(t, &urlDeadline, 50*time.Millisecond)
	tr.deadline = epoch.Add(urlDeadline)
	testutil.Swap(t, &dialTLS, func(_ context.Context, ip netip.Addr, port int, host string) (net.Conn, error) {
		assert.Equal(t, "93.184.216.34", ip.String())
		assert.Equal(t, 443, port)
		assert.Equal(t, "example.com", host)
		if err := tr.wait(d.connect); err != nil {
			return nil, err
		}
		c := &fakeConn{tr: tr, chunks: append([]chunk{}, parts...), sendDelay: d.send}
		tr.conns = append(tr.conns, c)
		if err := tr.wait(d.handshake); err != nil {
			c.closed = true
			return nil, err
		}
		return c, nil
	})
	return tr
}

func (tr *transfer) allClosed() bool {
	for _, c := range tr.conns {
		if !c.closed {
			return false
		}
	}
	return true
}

func download(t *testing.T, dest string) error {
	return downloadCapped(urlTarget{"example.com", 443, "/skill", exampleIP}, dest, now().Add(urlDeadline))
}

const ms = time.Millisecond

var fixed = []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
var chunked = []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// test_trickle_cannot_outlive_deadline
func TestTrickleCannotOutliveDeadline(t *testing.T) {
	cases := map[string][]chunk{
		"body":       {{fixed, 0}, {[]byte("abcdefgh"), 20 * ms}},
		"status":     {{[]byte("HTTP/1.1 200 OK\r\n"), 20 * ms}, {[]byte("Content-Length: 8\r\n\r\nabcdefgh"), 0}},
		"header":     {{[]byte("HTTP/1.1 200 OK\r\n"), 0}, {[]byte("X-Slow: abcdefgh\r\n"), 20 * ms}, {[]byte("Content-Length: 8\r\n\r\nabcdefgh"), 0}},
		"chunk-size": {{chunked, 0}, {[]byte("8;extension=abcdefgh\r\n"), 20 * ms}, {[]byte("abcdefgh\r\n0\r\n\r\n"), 0}},
		"chunk-body": {{cat(chunked, []byte("8\r\n")), 0}, {[]byte("abcdefgh"), 20 * ms}, {[]byte("\r\n0\r\n\r\n"), 0}},
		"trailer":    {{cat(chunked, []byte("8\r\nabcdefgh\r\n0\r\n")), 0}, {[]byte("X-Trailer: abcdefgh\r\n\r\n"), 20 * ms}},
		"until-eof":  {{[]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"), 0}, {[]byte("abcdefgh"), 20 * ms}},
	}
	for name, parts := range cases {
		t.Run(name, func(t *testing.T) {
			tr := setupTransfer(t, parts, delays{}, false)
			err := download(t, filepath.Join(t.TempDir(), "out"))
			isLimit(t, err)
			assert.Contains(t, err.Error(), "deadline")
			assert.LessOrEqual(t, tr.clock, 50*ms)
			assert.True(t, tr.allClosed())
		})
	}
}

// test_setup_and_request_share_download_budget
func TestSetupAndRequestShareDownloadBudget(t *testing.T) {
	for name, d := range map[string]delays{
		"connect":   {connect: 80 * ms},
		"handshake": {handshake: 80 * ms},
		"combined":  {connect: 30 * ms, handshake: 30 * ms},
		"request":   {send: 20 * ms},
	} {
		t.Run(name, func(t *testing.T) {
			tr := setupTransfer(t, []chunk{{cat(fixed, []byte("abcdefgh")), 0}}, d, false)
			err := download(t, filepath.Join(t.TempDir(), "out"))
			isLimit(t, err)
			assert.Contains(t, err.Error(), "deadline")
			assert.LessOrEqual(t, tr.clock, 50*ms)
			assert.True(t, tr.allClosed())
		})
	}
}

// test_on_time_transfer_preserves_bytes_and_tls_checks
func TestOnTimeTransferPreservesBytesAndTLSChecks(t *testing.T) {
	for name, response := range map[string][]byte{
		"fixed":   cat(fixed, []byte("abcdefgh")),
		"chunked": cat(chunked, []byte("8\r\nabcdefgh\r\n0\r\n\r\n")),
	} {
		t.Run(name, func(t *testing.T) {
			tr := setupTransfer(t, []chunk{{response, 0}}, delays{connect: 5 * ms, handshake: 5 * ms}, false)
			out := filepath.Join(t.TempDir(), "out")
			require.NoError(t, download(t, out))
			got, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, "abcdefgh", string(got))
			assert.True(t, tr.allClosed())
			assert.Less(t, tr.clock, 50*ms)
			for i, timeout := range tr.timeouts {
				assert.LessOrEqual(t, timeout, 50*ms)
				if i > 0 {
					assert.LessOrEqual(t, timeout, tr.timeouts[i-1])
				}
			}
		})
	}
}

// test_successful_io_returning_after_deadline_is_not_accepted
func TestSuccessfulIOReturningAfterDeadlineIsNotAccepted(t *testing.T) {
	for _, stage := range []string{"handshake", "request", "read"} {
		t.Run(stage, func(t *testing.T) {
			var readDelay, hs, send time.Duration
			switch stage {
			case "read":
				readDelay = 80 * ms
			case "handshake":
				hs = 80 * ms
			case "request":
				send = 80 * ms
			}
			tr := setupTransfer(t, []chunk{{fixed, 0}, {[]byte("abcdefgh"), readDelay}}, delays{handshake: hs, send: send}, true)
			err := download(t, filepath.Join(t.TempDir(), "out"))
			isLimit(t, err)
			assert.Contains(t, err.Error(), "deadline")
			assert.True(t, tr.allClosed())
		})
	}
}

// test_idle_socket_timeout_is_not_mislabeled_as_whole_download_deadline
func TestIdleSocketTimeoutIsNotMislabeledAsWholeDownloadDeadline(t *testing.T) {
	testutil.Swap(t, &urlTimeout, 10*ms)
	tr := setupTransfer(t, []chunk{{fixed, 0}, {[]byte("abcdefgh"), 20 * ms}}, delays{}, false)
	err := download(t, filepath.Join(t.TempDir(), "out"))
	require.Error(t, err)
	var ne net.Error
	assert.True(t, errors.As(err, &ne) && ne.Timeout(), "want a socket timeout, got %T: %v", err, err)
	assert.False(t, errors.As(err, &ingestLimitExceededError{}))
	assert.Less(t, tr.clock, 50*ms)
	assert.True(t, tr.allClosed())
}

// test_deadline_failure_removes_url_temporary_directory
func TestDeadlineFailureRemovesURLTemporaryDirectory(t *testing.T) {
	setupTransfer(t, []chunk{{fixed, 0}, {[]byte("abcdefgh"), 20 * ms}}, delays{}, false)
	testutil.Swap(t, &checkURLHost, fakeHost("/skill"))
	temporary := filepath.Join(t.TempDir(), "download")
	require.NoError(t, os.Mkdir(temporary, 0o755))
	testutil.Swap(t, &mkdtemp, func() (string, error) { return temporary, nil })
	_, _, _, err := fetchURL("https://example.com/skill")
	isLimit(t, err)
	assert.Contains(t, err.Error(), "deadline")
	assert.NoDirExists(t, temporary)
}

// test_dns_and_transfer_share_one_deadline
func TestDNSAndTransferShareOneDeadline(t *testing.T) {
	tr := setupTransfer(t, []chunk{{fixed, 0}, {[]byte("abcdefgh"), 20 * ms}}, delays{}, false)
	testutil.Swap(t, &checkURLHost, func(_ string, deadline time.Time) (urlTarget, error) {
		assert.Equal(t, epoch.Add(50*ms), deadline)
		tr.clock += 40 * ms
		return urlTarget{"example.com", 443, "/skill", exampleIP}, nil
	})
	_, _, _, err := fetchURL("https://example.com/skill")
	isLimit(t, err)
	assert.Contains(t, err.Error(), "deadline")
	assert.LessOrEqual(t, tr.clock, 50*ms)
	assert.True(t, tr.allClosed())
}

// test_stalled_dns_is_bounded_before_download
func TestStalledDNSIsBoundedBeforeDownload(t *testing.T) {
	tr := setupTransfer(t, nil, delays{}, false)
	testutil.Swap(t, &lookupIP, func(ctx context.Context, host string) ([]netip.Addr, error) {
		assert.Equal(t, "example.com", host)
		dl, ok := ctx.Deadline()
		assert.True(t, ok)
		assert.LessOrEqual(t, time.Until(dl), 50*ms)
		tr.clock += 50 * ms
		return nil, context.DeadlineExceeded
	})
	_, err := checkURLHost("https://example.com/skill", epoch.Add(50*ms))
	isLimit(t, err)
	assert.Contains(t, err.Error(), "deadline")
	assert.Empty(t, tr.conns)
}

// test_bounded_dns_preserves_all_address_ssrf_checks
func TestBoundedDNSPreservesAllAddressSsrfChecks(t *testing.T) {
	for _, ips := range [][]string{{"93.184.216.34"}, {"93.184.216.34", "127.0.0.1"}, {"::ffff:169.254.169.254"}} {
		t.Run(ips[len(ips)-1], func(t *testing.T) {
			setupTransfer(t, nil, delays{}, false)
			testutil.Swap(t, &lookupIP, addrs(ips...))
			got, err := checkURLHost("https://example.com/skill", epoch.Add(50*ms))
			if len(ips) == 1 && ips[0] == "93.184.216.34" {
				require.NoError(t, err)
				assert.Equal(t, ips[0], got.ip.String())
				return
			}
			isUnsafe(t, err)
			assert.Contains(t, err.Error(), "non-public")
		})
	}
}

// test_real_isolated_dns_worker_resolves_numeric_literal_without_network
func TestRealDNSResolvesNumericLiteralWithoutNetwork(t *testing.T) {
	got, err := checkURLHost("https://93.184.216.34/skill", time.Now().Add(5*time.Second))
	require.NoError(t, err)
	assert.Equal(t, urlTarget{"93.184.216.34", 443, "/skill", exampleIP}, got)
}

// test_dns_worker_failure_never_reaches_connect
func TestDNSWorkerFailureNeverReachesConnect(t *testing.T) {
	for _, failure := range []string{"process", "malformed", "late"} {
		t.Run(failure, func(t *testing.T) {
			tr := setupTransfer(t, nil, delays{}, false)
			testutil.Swap(t, &lookupIP, func(context.Context, string) ([]netip.Addr, error) {
				switch failure {
				case "process":
					return nil, errors.New("private worker detail")
				case "late":
					tr.clock = 60 * ms
					return []netip.Addr{exampleIP}, nil
				}
				return nil, errors.New("malformed reply: {")
			})
			_, err := checkURLHost("https://example.com/skill", epoch.Add(50*ms))
			if failure == "late" {
				isLimit(t, err)
			} else {
				isUnsafe(t, err)
			}
			assert.NotContains(t, err.Error(), "private worker detail")
			assert.Empty(t, tr.conns)
		})
	}
}
