package ingest

// Turn a scan target into a local directory to walk. A target may be a directory,
// a single file, a .zip archive, an https URL, or a git repository (an https .git
// URL). Directories are used in place; files, archives, URLs and clones are
// materialised into a temporary directory the returned cleanup removes. Downloads,
// zip bombs and zip-slip archives are bounded and cannot write outside the extract
// dir; failures fail closed. Only the URL and git adapters touch the network, and
// both refuse a host that resolves to a non-public address at check time.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// Aggregate limits; a breach fails closed. They bound the download, the total
// uncompressed size of an archive and the on-disk size of a clone, not any
// single file, which the walker caps.
var (
	ingestMaxBytes      int64 = 100 << 20
	ingestMaxZipMembers       = 10000
	urlTimeout                = 30 * time.Second  // per-operation socket timeout
	urlDeadline               = 120 * time.Second // wall-clock cap on the whole download
	gitTimeout                = 120 * time.Second
)

var redirectStatuses = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// Single-file inputs that are archives skill-xray does not extract; copied in as
// one opaque asset they would report 100% coverage, so they are refused.
var archiveExts = []string{".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".rar", ".7z", ".lz", ".lzma", ".zst"}

// Resolved is the local directory a target became. Kind is one of directory,
// file, zip, url, git.
type Resolved struct{ Root, Name, Kind string }

// unsafeInputError: the target is malformed, unreachable, or points somewhere unsafe.
type unsafeInputError struct{ Msg string }

func (e unsafeInputError) Error() string { return e.Msg }

// ingestLimitExceededError: a size or count limit was exceeded; ingest fails closed.
type ingestLimitExceededError struct{ Msg string }

func (e ingestLimitExceededError) Error() string { return e.Msg }

func refuse(format string, a ...any) error { return unsafeInputError{fmt.Sprintf(format, a...)} }
func limit(format string, a ...any) error  { return ingestLimitExceededError{fmt.Sprintf(format, a...)} }

// failClosed keeps our two error types and wraps anything else as an
// unsafeInputError built with format (one %s for the cause).
func failClosed(err error, format string, a ...any) error {
	if errors.As(err, &unsafeInputError{}) || errors.As(err, &ingestLimitExceededError{}) {
		return err
	}
	return refuse(format, append(a, err)...)
}

// Seams the tests replace: the clock, temp-dir creation, DNS, the TLS dial, the git
// subprocess and the two host checks.
var (
	now      = time.Now
	mkdtemp  = func() (string, error) { return os.MkdirTemp("", "skillxray-") }
	lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	dialTLS        = dialTLSDefault
	runGit         = runGitDefault
	checkURLHost   = checkURLHostDefault
	checkGitRemote = checkGitRemoteDefault
)

// rmtree removes a temp tree. git marks its pack files read-only, and a read-only
// POSIX directory blocks unlinking; clear the bits and retry so cleanup runs. A
// symlink is never chmod'ed: that would change its target outside the tree.
func rmtree(p string) {
	if os.RemoveAll(p) == nil {
		return
	}
	_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink == 0 {
			if st, err := os.Lstat(q); err == nil {
				_ = os.Chmod(q, st.Mode()|0o700) // #nosec G122 -- our own temp tree; symlinks were skipped above
			}
		}
		return nil
	})
	_ = os.RemoveAll(p)
}

// Resolve materialises target and returns where to walk it plus a cleanup that
// removes any temporary directory (a no-op for a directory target).
func Resolve(target string) (Resolved, func(), error) {
	noop := func() {}
	// Local paths are checked first, so a directory or file named `foo.git` is
	// treated as what it is on disk, not routed to the git adapter.
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		abs, err := filepath.Abs(target)
		if err != nil {
			abs = target
		}
		name := baseName(strings.TrimRight(abs, `/\`))
		if name == "" {
			name = abs
		}
		return Resolved{abs, name, "directory"}, noop, nil
	} else if err == nil && st.Mode().IsRegular() {
		f, err := openTarget(target)
		if err != nil {
			return Resolved{}, noop, err
		}
		defer f.Close()
		if looksLikeZip(f) {
			tmp, err := mkdtemp()
			if err != nil {
				return Resolved{}, noop, refuse("cannot read zip %s: %s", target, err)
			}
			if err := extractZip(f, tmp); err != nil {
				rmtree(tmp)
				return Resolved{}, noop, failClosed(err, "cannot read zip %s: %s", target)
			}
			return Resolved{tmp, trimSuffixFold(baseName(target), ".zip"), "zip"}, func() { rmtree(tmp) }, nil
		}
		if isUnsupportedArchive(f, target) {
			return Resolved{}, noop, refuse("%s is an archive skill-xray does not extract; unpack it and scan the directory", baseName(target))
		}
		tmp, err := wrapSingleFile(f, target)
		if err != nil {
			return Resolved{}, noop, err
		}
		return Resolved{tmp, baseName(target), "file"}, func() { rmtree(tmp) }, nil
	}
	if looksLikeGit(target) {
		tmp, name, err := gitClone(target)
		if err != nil {
			return Resolved{}, noop, err
		}
		return Resolved{tmp, name, "git"}, func() { rmtree(tmp) }, nil
	}
	if looksLikeURL(target) {
		root, tmp, name, err := fetchURL(target)
		if err != nil {
			return Resolved{}, noop, err
		}
		return Resolved{root, name, "url"}, func() { rmtree(tmp) }, nil
	}
	return Resolved{}, noop, refuse("not a directory, file, .zip, URL or git repo: %s", target)
}

func looksLikeGit(target string) bool {
	t := pytext.Lower(pytext.Strip(target))
	return strings.HasSuffix(t, ".git") || strings.HasPrefix(t, "git@") || strings.HasPrefix(t, "git://") || strings.HasPrefix(t, "ssh://")
}

func looksLikeURL(target string) bool {
	return strings.HasPrefix(pytext.Lower(pytext.Strip(target)), "https://")
}

// trimSuffixFold strips an ASCII suffix (.zip, .git) matched case-insensitively.
func trimSuffixFold(name, suffix string) string {
	if strings.HasSuffix(pytext.Lower(name), suffix) {
		return name[:len(name)-len(suffix)]
	}
	return name
}

// isUnsupportedArchive is true for a tar (plain, gzip, bzip2 or xz) or a file whose
// name carries another archive extension.
func isUnsupportedArchive(f *os.File, name string) bool {
	low := pytext.Lower(name)
	return isTar(f) || slices.ContainsFunc(archiveExts, func(e string) bool { return strings.HasSuffix(low, e) })
}

// openTarget opens a single-file target once, without following a symlink or a junction in its
// final component, and checks on the handle that it is a regular file; every later read of the
// target goes through that handle, so nothing swapped in after the check is read. A link among
// the directories on the way is part of the path the operator named, as for any file name.
func openTarget(target string) (*os.File, error) {
	f, err := openNoFollow(target)
	if err != nil {
		return nil, failClosed(err, "cannot read file %s: %s", target)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, refuse("single-file input is not a regular file; refused: %s", target)
	}
	return f, nil
}

func tarHeader(r io.Reader) bool {
	_, err := tar.NewReader(r).Next()
	return err == nil
}

func isTar(f *os.File) bool {
	at := func() io.Reader { return io.NewSectionReader(f, 0, 1<<62) } // a fresh read from offset 0
	if gz, err := gzip.NewReader(at()); err == nil && tarHeader(gz) {
		return true
	}
	if tarHeader(bzip2.NewReader(at())) {
		return true
	}
	var magic [6]byte
	// ponytail: no stdlib xz decoder, so any xz stream is refused as a tar (fail
	// closed); upgrade path: github.com/ulikunitz/xz and sniff the tar header.
	if _, err := io.ReadFull(at(), magic[:]); err == nil && magic == [6]byte{0xfd, '7', 'z', 'X', 'Z', 0} {
		return true
	}
	return tarHeader(at())
}

// zipMemberExtracts is true only for a member extractZip would write as a file:
// not a directory and not a name that normalises to the extraction root.
func zipMemberExtracts(f *zip.File) bool {
	if strings.HasSuffix(f.Name, "/") {
		return false
	}
	return path.Clean(strings.ReplaceAll(f.Name, "\\", "/")) != "."
}

// looksLikeZip: a zip only if it BEGINS with a local file header AND the central
// directory lists a member that would actually extract to a file. A bare EOCD
// trailer appended to any file reads as a valid empty zip and would leave an empty
// package at 100%; anything without a real member takes the single-file path.
func looksLikeZip(f *os.File) bool {
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "PK\x03\x04" {
		return false
	}
	r, err := zipReader(f)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(r.File, zipMemberExtracts)
}

// zipReader reads the central directory through the open descriptor; an insecure member name
// is left for extractZip to refuse.
func zipReader(f *os.File) (*zip.Reader, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	r, err := zip.NewReader(io.NewSectionReader(f, 0, st.Size()), st.Size())
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, err
	}
	return r, nil
}

func wrapSingleFile(f *os.File, p string) (string, error) {
	// Copy in bounded chunks rather than a pre-copy size check: a file that grows
	// after the check must still not write more than ingestMaxBytes.
	tmp, err := mkdtemp()
	if err != nil {
		return "", refuse("cannot read file %s: %s", p, err)
	}
	err = func() error {
		dst, err := os.Create(filepath.Join(tmp, baseName(p))) // #nosec G304 -- a base name under a fresh temp directory
		if err != nil {
			return err
		}
		defer dst.Close()
		_, err = io.Copy(cappedWriter{dst, new(int64), ingestMaxBytes, "file exceeds %d bytes"}, io.NewSectionReader(f, 0, 1<<62))
		return err
	}()
	if err != nil {
		rmtree(tmp)
		return "", failClosed(err, "cannot read file %s: %s", p)
	}
	return tmp, nil
}

// cappedWriter forwards to w, failing with limit(msg, capBytes) once more than
// capBytes have been seen; *n is the running total shared across writers.
type cappedWriter struct {
	w        io.Writer
	n        *int64
	capBytes int64
	msg      string
}

func (c cappedWriter) Write(p []byte) (int, error) {
	if *c.n += int64(len(p)); *c.n > c.capBytes {
		return 0, limit(c.msg, c.capBytes)
	}
	return c.w.Write(p)
}

var driveRE = regexp.MustCompile(`^[A-Za-z]:`)

// extractZip extracts into dest, refusing zip-slip, symlink members, colliding
// portable names, too many members and more than ingestMaxBytes of written bytes.
func extractZip(f *os.File, dest string) error {
	destReal := realpath(dest)
	r, err := zipReader(f)
	if err != nil {
		return err
	}
	if len(r.File) > ingestMaxZipMembers {
		return limit("zip has %d members (max %d)", len(r.File), ingestMaxZipMembers)
	}
	var written int64
	seen, files := map[string]bool{}, map[string]bool{}
	for _, info := range r.File {
		raw := pytext.NFC(strings.ReplaceAll(info.Name, "\\", "/"))
		if strings.HasPrefix(raw, "/") || driveRE.MatchString(raw) {
			return refuse("zip member uses an absolute path: %s", info.Name)
		}
		var parts, portable []string
		for _, part := range strings.Split(raw, "/") {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				return refuse("zip member escapes the extract dir: %s", info.Name)
			}
			parts = append(parts, part)
			portable = append(portable, pytext.CaseFold(strings.TrimRight(part, " .")))
		}
		if len(parts) == 0 {
			continue // degenerate member ("", ".") -> the root
		}
		for _, part := range portable {
			if part == "" || strings.Contains(part, ":") {
				return refuse("zip member has a non-portable path: %s", info.Name)
			}
		}
		key := strings.Join(portable, "/")
		collides := seen[key]
		for i := 1; i < len(portable) && !collides; i++ {
			collides = files[strings.Join(portable[:i], "/")]
		}
		if collides {
			return refuse("zip has colliding member paths: %s", info.Name)
		}
		seen[key] = true
		isDir := strings.HasSuffix(info.Name, "/")
		if !isDir {
			files[key] = true
		}
		// parts hold no "", "." or "..", and symlink members are refused, so the
		// joined path cannot leave destReal.
		out := filepath.Join(destReal, filepath.Join(parts...))
		if (info.ExternalAttrs>>16)&0o170000 == 0o120000 {
			return refuse("zip contains a symlink: %s", info.Name)
		}
		if isDir {
			if err := os.MkdirAll(out, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return err
		}
		if err := func() error {
			src, err := info.Open()
			if err != nil {
				return err
			}
			defer src.Close()
			dst, err := os.Create(out) // #nosec G304 -- out is a member path extractZip already checked
			if err != nil {
				return err
			}
			defer dst.Close()
			_, err = io.Copy(cappedWriter{dst, &written, ingestMaxBytes, "zip uncompressed size exceeds %d bytes"}, src) // #nosec G110 -- cappedWriter fails closed at ingestMaxBytes
			return err
		}(); err != nil {
			return err
		}
	}
	return nil
}

// --- network adapters: url, git -------------------------------------------

// Python 3.13.2 ipaddress tables (IPv4Address/IPv6Address._constants, dumped
// from the oracle interpreter): is_global is "not in the CGNAT public network and
// not is_private", where is_private is "in a private network and not in an
// exception"; multicast is therefore global on both families.
var (
	cgnat    = netip.MustParsePrefix("100.64.0.0/10")
	private4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32")
	private4Exceptions = prefixes("192.0.0.9/32", "192.0.0.10/32")
	private6           = prefixes("::1/128", "::/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "3fff::/20", "fc00::/7", "fe80::/10")
	private6Exceptions = prefixes("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48",
		"2001:20::/28", "2001:30::/28")
)

func prefixes(ps ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ps))
	for i, p := range ps {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// isGlobal is ipaddress.is_global for an unmapped address (Python answers for the
// embedded IPv4 of a mapped one, which is what Unmap gives the caller).
func isGlobal(ip netip.Addr) bool {
	if ip.Is4() {
		return !cgnat.Contains(ip) && !(inAny(ip, private4) && !inAny(ip, private4Exceptions))
	}
	return !(inAny(ip, private6) && !inAny(ip, private6Exceptions))
}

// embeddedIPv4 is the IPv4 a NAT64 (64:ff9b::/96) address carries; is_global does
// not look through it, so a v6 literal could smuggle link-local IPv4 past the guard.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !nat64Prefix.Contains(ip) {
		return netip.Addr{}, false
	}
	b := ip.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}

func downloadTimeout(deadline time.Time) (time.Duration, error) {
	remaining := deadline.Sub(now())
	if remaining <= 0 {
		return 0, limit("download exceeded the %ds deadline", int(urlDeadline/time.Second))
	}
	return min(urlTimeout, remaining), nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// resolvePublicIP resolves host and returns the first address, refusing if ANY
// resolved address (or an IPv4 it embeds) is non-public. A zero deadline means
// no time bound.
func resolvePublicIP(host string, deadline time.Time) (netip.Addr, error) {
	ctx := context.Background()
	if !deadline.IsZero() {
		d, err := downloadTimeout(deadline)
		if err != nil {
			return netip.Addr{}, err
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	addrs, err := lookupIP(ctx, host)
	if err != nil {
		if isTimeout(err) {
			if !deadline.IsZero() {
				if _, derr := downloadTimeout(deadline); derr != nil {
					return netip.Addr{}, derr
				}
			}
			return netip.Addr{}, refuse("DNS resolution timed out")
		}
		return netip.Addr{}, refuse("cannot resolve host: %s", host)
	}
	if !deadline.IsZero() {
		if _, err := downloadTimeout(deadline); err != nil {
			return netip.Addr{}, err
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, refuse("host did not resolve: %s", host)
	}
	for i, ip := range addrs {
		if ip.Zone() != "" {
			// A scoped literal ("fe80::1%lo0") is what ipaddress cannot parse; fail closed.
			return netip.Addr{}, refuse("host resolved to an unparseable address (%s); refused", ip)
		}
		ip = ip.Unmap()
		addrs[i] = ip
		embedded, ok := embeddedIPv4(ip)
		if !isGlobal(ip) || (ok && !isGlobal(embedded)) {
			return netip.Addr{}, refuse("host resolves to a non-public address (%s); refused", ip)
		}
	}
	return addrs[0], nil
}

type urlTarget struct {
	host   string
	port   int
	target string
	ip     netip.Addr
}

// checkURLHostDefault validates scheme, port and host. https only, matching the
// git adapter. A malformed URL fails closed without echoing the URL (it can carry
// userinfo or a query token).
func checkURLHostDefault(rawurl string, deadline time.Time) (urlTarget, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return urlTarget{}, refuse("malformed URL")
	}
	if u.Scheme != "https" {
		return urlTarget{}, refuse("only https URLs are allowed")
	}
	if u.User != nil {
		return urlTarget{}, refuse("URL with embedded credentials is refused")
	}
	host := pytext.Lower(u.Hostname())
	if host == "" {
		return urlTarget{}, refuse("no host in URL")
	}
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return urlTarget{}, refuse("malformed URL")
		}
		if n != 0 {
			port = n
		}
	}
	ip, err := resolvePublicIP(host, deadline)
	if err != nil {
		return urlTarget{}, err
	}
	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	return urlTarget{host, port, target, ip}, nil
}

// deadlineConn bounds every socket operation by min(urlTimeout, remaining) and
// re-checks the deadline afterwards, so HTTP buffering cannot hide a slow peer
// and an operation that completes late is still refused.
type deadlineConn struct {
	net.Conn
	deadline time.Time
}

func (c *deadlineConn) op(set func(time.Time) error, do func() (int, error)) (int, error) {
	d, err := downloadTimeout(c.deadline)
	if err != nil {
		return 0, err
	}
	_ = set(time.Now().Add(d))
	n, err := do()
	if _, derr := downloadTimeout(c.deadline); derr != nil {
		return 0, derr
	}
	return n, err
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	return c.op(c.Conn.SetReadDeadline, func() (int, error) { return c.Conn.Read(b) })
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	return c.op(c.Conn.SetWriteDeadline, func() (int, error) { return c.Conn.Write(b) })
}

func dialTLSDefault(ctx context.Context, ip netip.Addr, port int, host string) (net.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String()) // #nosec G115 -- port was range-checked by checkURLHostDefault
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: host})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// downloadCapped fetches target from the validated ip into dest: pinned to that
// IP (no DNS rebinding), redirects refused, body capped, every step under the
// shared deadline.
func downloadCapped(t urlTarget, dest string, deadline time.Time) error {
	d, err := downloadTimeout(deadline)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	raw, err := dialTLS(ctx, t.ip, t.port, t.host)
	if err != nil {
		return afterDeadline(err, deadline)
	}
	conn := &deadlineConn{Conn: raw, deadline: deadline}
	defer conn.Close()
	if _, err := downloadTimeout(deadline); err != nil {
		return err
	}
	hostHeader := strings.TrimSuffix(net.JoinHostPort(t.host, strconv.Itoa(t.port)), ":443")
	req := &http.Request{Method: "GET", ProtoMajor: 1, ProtoMinor: 1, Host: hostHeader,
		URL:    &url.URL{Scheme: "https", Host: hostHeader, Opaque: t.target},
		Header: http.Header{"User-Agent": {"skill-xray"}}}
	if err := req.Write(conn); err != nil {
		return afterDeadline(err, deadline)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return afterDeadline(err, deadline)
	}
	defer resp.Body.Close()
	if _, err := downloadTimeout(deadline); err != nil {
		return err
	}
	if redirectStatuses[resp.StatusCode] {
		return refuse("URL redirected (HTTP %d); pass the final URL directly", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return refuse("URL returned HTTP %d", resp.StatusCode)
	}
	fh, err := os.Create(dest) // #nosec G304 -- a constant name under a fresh temp directory
	if err != nil {
		return err
	}
	defer fh.Close()
	buf := make([]byte, 65536)
	var written int64
	for {
		if _, err := downloadTimeout(deadline); err != nil {
			return err
		}
		n, err := resp.Body.Read(buf)
		if _, derr := downloadTimeout(deadline); derr != nil {
			return derr
		}
		written += int64(n)
		if written > ingestMaxBytes {
			return limit("download exceeds %d bytes", ingestMaxBytes)
		}
		if _, werr := fh.Write(buf[:n]); werr != nil {
			return werr
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// afterDeadline reports the deadline breach when one explains err, else err itself.
func afterDeadline(err error, deadline time.Time) error {
	if _, derr := downloadTimeout(deadline); derr != nil {
		return derr
	}
	return err
}

// fetchURL returns (root to walk, temp dir to remove, package name).
func fetchURL(rawurl string) (root, tmp, name string, err error) {
	deadline := now().Add(urlDeadline)
	t, err := checkURLHost(rawurl, deadline)
	if err != nil {
		return "", "", "", err
	}
	tmp, err = mkdtemp()
	if err != nil {
		return "", "", "", refuse("failed to fetch URL: %s", err)
	}
	root, name, err = fetchInto(rawurl, t, tmp, deadline)
	if err != nil {
		rmtree(tmp)
		return "", "", "", failClosed(err, "failed to fetch URL: %s")
	}
	return root, tmp, name, nil
}

func fetchInto(rawurl string, t urlTarget, tmp string, deadline time.Time) (root, name string, err error) {
	download := filepath.Join(tmp, "download")
	if err := downloadCapped(t, download, deadline); err != nil {
		return "", "", err
	}
	if u, err := url.Parse(rawurl); err == nil {
		name = pytext.Basename(u.EscapedPath())
	}
	if name == "" || name == "." || name == ".." {
		name = "download"
	}
	f, err := os.Open(download) // #nosec G304 -- a constant name under a fresh temp directory
	if err != nil {
		return "", "", err
	}
	if looksLikeZip(f) {
		extract := filepath.Join(tmp, "extracted")
		if err := os.Mkdir(extract, 0o750); err != nil {
			f.Close()
			return "", "", err
		}
		err := extractZip(f, extract)
		f.Close()
		if err != nil {
			return "", "", err
		}
		if err := os.Remove(download); err != nil {
			return "", "", err
		}
		return extract, trimSuffixFold(name, ".zip"), nil
	}
	unsupported := isUnsupportedArchive(f, name)
	f.Close()
	if unsupported {
		return "", "", refuse("downloaded file is an archive skill-xray does not extract; fetch and unpack it, then scan the directory")
	}
	dest := filepath.Join(tmp, name)
	if dest != download {
		if err := os.Rename(download, dest); err != nil {
			return "", "", err
		}
	}
	return tmp, name, nil
}

// checkGitRemoteDefault: https only, so the validated-public-IP check applies; git://
// and ssh:// cannot be SSRF-checked the same way.
func checkGitRemoteDefault(rawurl string) error {
	if !strings.HasPrefix(pytext.Lower(rawurl), "https://") {
		return refuse("git ingest supports https:// repository URLs only")
	}
	_, err := checkURLHost(rawurl, time.Time{})
	return err
}

func runGitDefault(ctx context.Context, argv, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- git with fixed flags and a URL checkGitRemoteDefault validated
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.Bytes(), err
}

// gitClone clones a validated https repository with a depth-1 clone, no prompts,
// no system/user config (which could rewrite the URL or set a proxy), no proxy
// environment and no redirects, then checks the tree size.
func gitClone(rawurl string) (tmp, name string, err error) {
	if err := checkGitRemote(rawurl); err != nil {
		return "", "", err
	}
	tmp, err = mkdtemp()
	if err != nil {
		return "", "", refuse("git clone failed: %s", err)
	}
	env := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	argv := []string{"git", "-c", "http.followRedirects=false", "-c", "http.proxy=",
		"clone", "--depth", "1", "--single-branch", "--no-tags", rawurl, tmp}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	stderr, err := runGit(ctx, argv, env)
	if err == nil {
		err = enforceTreeSize(tmp)
	}
	if err != nil {
		rmtree(tmp)
		switch {
		case errors.As(err, &ingestLimitExceededError{}):
			return "", "", err
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return "", "", limit("git clone timed out after %ds", int(gitTimeout/time.Second))
		case errors.Is(err, exec.ErrNotFound):
			return "", "", refuse("git is not installed")
		}
		detail := []rune(pytext.Strip(strings.ToValidUTF8(string(stderr), "�")))
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return "", "", refuse("git clone failed: %s", string(detail))
	}
	return tmp, trimSuffixFold(baseName(strings.TrimRight(rawurl, "/")), ".git"), nil
}

func enforceTreeSize(root string) error {
	var total int64
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		st, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		total += st.Size()
		if total > ingestMaxBytes {
			return limit("cloned tree exceeds %d bytes", ingestMaxBytes)
		}
		return nil
	})
}
