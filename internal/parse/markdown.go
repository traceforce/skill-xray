package parse

// Python parse.parse_markdown over goldmark. goldmark supplies the
// CommonMark block and inline structure; the markdown-it token facts it does not expose (block
// line maps, fence opener and closer lines, code-span markup, link href normalisation) are
// recovered here, and x/net/html replaces html.parser for the tolerant HTML inspection.
// Every column is a 1-based code-point index and every line a 1-based index into the
// newline-normalised text.

import (
	"bytes"
	"fmt"
	"html"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	xhtml "golang.org/x/net/html"
	"golang.org/x/net/idna"

	"github.com/traceforce/skill-xray/internal/pytext"
)

// MaxPreprocTokens is parse.MAX_PREPROC_TOKENS; test_parser_and_output_caps_share_one_contract
// pins it to the finding cap.
const MaxPreprocTokens = 25

// normNewlines is parse._norm_newlines: CRLF and lone CR become LF.
func normNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// --- goldmark: block parsers wrapped to record the lines markdown-it's token maps carry ---

// blockLines is what goldmark drops: the 0-based line a block was opened on, the byte offset of
// that line's container content, and the closer line of a fenced code block (-1 when none).
type blockLines struct{ open, content, close int }

var blockLinesKey = parser.NewContextKey()

type lineRecorder struct{ parser.BlockParser }

func recorded(pc parser.Context) map[ast.Node]*blockLines {
	return pc.ComputeIfAbsent(blockLinesKey, func() any { return map[ast.Node]*blockLines{} }).(map[ast.Node]*blockLines)
}

func (r lineRecorder) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	node, state := r.BlockParser.Open(parent, reader, pc)
	if node != nil {
		line, seg := reader.Position()
		recorded(pc)[node] = &blockLines{line, seg.Start, -1}
	}
	return node, state
}

func (r lineRecorder) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	if item, ok := node.(*ast.ListItem); ok {
		if line, _ := reader.PeekLine(); util.IsBlank(line) {
			// goldmark advances a blank line to EOL here; markdown-it keeps what lies past the
			// item indent, so a fence or indented code block inside the item sees the spaces.
			if pos, padding := util.IndentPosition(line, reader.LineOffset(), item.Offset); pos >= 0 {
				reader.AdvanceAndSetPadding(pos, padding)
			} else {
				reader.AdvanceToEOL()
			}
			return parser.Continue | parser.HasChildren
		}
	}
	state := r.BlockParser.Continue(node, reader, pc)
	if state&parser.Close != 0 && node.Kind() == ast.KindFencedCodeBlock {
		line, _ := reader.Position()
		recorded(pc)[node].close = line
	}
	return state
}

var mdParser = func() parser.Parser {
	var blocks []util.PrioritizedValue
	for _, pv := range parser.DefaultBlockParsers() {
		blocks = append(blocks, util.Prioritized(lineRecorder{pv.Value.(parser.BlockParser)}, pv.Priority))
	}
	return parser.NewParser(parser.WithBlockParsers(blocks...),
		parser.WithInlineParsers(parser.DefaultInlineParsers()...),
		parser.WithParagraphTransformers(parser.DefaultParagraphTransformers()...))
}()

// --- parse_markdown ---

// mdMaxMarkers bounds what goldmark parses quadratically on one line: nested container markers
// ('>' and list bullets, each opening a container) and link openers with unclosed destinations.
// 600k leading '>' never finish where markdown-it-py takes 4 s, so a line past the bound is
// refused as markdown_too_complex; the bound is an accepted difference from the Python scanner
// that no real skill reaches.
const mdMaxMarkers = 10000

// markdownTooComplex returns the count of the first line over mdMaxMarkers, else 0.
func markdownTooComplex(body string) int {
	for line := range strings.Lines(body) {
		if len(line) <= mdMaxMarkers {
			continue
		}
		if n := max(leadingMarkers(line), strings.Count(line, "](")); n > mdMaxMarkers {
			return n
		}
	}
	return 0
}

// leadingMarkers counts the blockquote and list markers that open the line, the run goldmark
// turns into nested containers.
func leadingMarkers(line string) int {
	n := 0
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '>':
			n++
			i++
		case (c == '-' || c == '*' || c == '+') && i+1 < len(line) && (line[i+1] == ' ' || line[i+1] == '\t'):
			n++
			i += 2
		case c >= '0' && c <= '9':
			j := i
			for j < len(line) && line[j] >= '0' && line[j] <= '9' {
				j++
			}
			if j+1 < len(line) && (line[j] == '.' || line[j] == ')') && (line[j+1] == ' ' || line[j+1] == '\t') {
				n++
				i = j + 2
				continue
			}
			return n
		default:
			return n
		}
	}
	return n
}

type mdDoc struct {
	src       []byte
	lines     []string
	lineStart []int
	off       int
	md        *Markdown
	blocks    map[ast.Node]*blockLines
	excluded  map[int]bool // 0-based lines of fences and indented code
	starts    map[int]bool // 0-based first lines of html blocks and prose inlines
	refSeen   map[string]bool
}

// parseMarkdown is parse.parse_markdown. Line numbers are offset by lineOffset (the frontmatter
// height). goldmark cannot fail, so there is no error value.
func parseMarkdown(body string, lineOffset int) *Markdown {
	body = normNewlines(body)
	d := &mdDoc{src: []byte(body), lines: strings.Split(body, "\n"), off: lineOffset, md: &Markdown{},
		excluded: map[int]bool{}, starts: map[int]bool{}, refSeen: map[string]bool{}}
	d.lineStart = make([]int, len(d.lines))
	for i, pos := 1, 0; i < len(d.lines); i++ {
		pos += len(d.lines[i-1]) + 1
		d.lineStart[i] = pos
	}
	ctx := parser.NewContext()
	root := mdParser.Parse(text.NewReader(d.src), parser.WithContext(ctx))
	d.blocks = recorded(ctx)
	d.walk(root)
	inline, total := scanInlinePreproc(body, lineOffset, d.excluded, true, d.starts)
	d.md.Preproc = append(d.md.Preproc, inline...)
	d.md.PreprocCounts.Inline = total
	return d.md
}

// lineOf is the 0-based line holding byte offset pos.
func (d *mdDoc) lineOf(pos int) int { return sort.SearchInts(d.lineStart, pos+1) - 1 }

// span converts a markdown-it map [start, end) to the 1-based inclusive file span.
func (d *mdDoc) span(start, end int) Span { return Span{start + 1 + d.off, end + d.off} }

func (d *mdDoc) rawLines(start, end int) string { return strings.Join(d.lines[start:end], "\n") }

func (d *mdDoc) walk(n ast.Node) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch b := c.(type) {
		case *ast.FencedCodeBlock:
			d.fence(b)
		case *ast.CodeBlock:
			d.codeBlock(b)
		case *ast.HTMLBlock:
			d.htmlBlock(b)
		case *ast.Paragraph:
			_, top := b.Parent().(*ast.Document)
			d.inline(b, top)
		case *ast.TextBlock, *ast.Heading:
			d.inline(c, false)
		case *ast.LinkReferenceDefinition:
			d.reference(b)
		default:
			d.walk(c)
		}
	}
}

// linesSpan is the map of a block from its Lines(): first line to last line + 1.
func (d *mdDoc) linesSpan(n ast.Node) (start, end int) {
	ls := n.Lines()
	return d.lineOf(ls.At(0).Start), d.lineOf(ls.At(ls.Len()-1).Start) + 1
}

func (d *mdDoc) fence(b *ast.FencedCodeBlock) {
	bl := d.blocks[b]
	start, end := bl.open, bl.close+1
	if bl.close < 0 {
		end = start + 1
		if b.Lines().Len() > 0 {
			_, end = d.linesSpan(b)
		}
	}
	// The opener: the first non-space byte of the line's container content is the marker.
	i := bl.content
	for i < len(d.src) && (d.src[i] == ' ' || d.src[i] == '\t') {
		i++
	}
	marker := d.src[i]
	j := i
	for j < len(d.src) && d.src[j] == marker {
		j++
	}
	markup := string(d.src[i:j])
	lineEnd := d.lineStart[start] + len(d.lines[start])
	info := pytext.Strip(string(d.src[j:lineEnd]))
	code := d.segText(b.Lines())
	if bl.close < 0 && !bytes.HasSuffix(d.src, []byte("\n")) {
		code = strings.TrimSuffix(code, "\n") // markdown-it keeps no LF the source lacks
	}
	d.code(info, code, start, end, true)
	if strings.HasPrefix(info, "!") {
		column := runeIndex([]rune(d.lines[start]), []rune(markup), 0) + 1
		if column == 0 {
			column = 1
		}
		if pytext.Strip(code) != "" {
			d.md.PreprocCounts.Fenced++
			if d.md.PreprocCounts.Fenced <= MaxPreprocTokens {
				d.md.Preproc = append(d.md.Preproc, Preproc{Kind: "fenced", Code: code, Line: start + 1 + d.off, Runs: true, Column: column, Info: info})
			}
		}
	}
}

func (d *mdDoc) codeBlock(b *ast.CodeBlock) {
	start, end := d.linesSpan(b)
	d.code("", d.segText(b.Lines()), start, end, false)
}

func (d *mdDoc) segText(segs *text.Segments) string {
	var b strings.Builder
	for k := 0; k < segs.Len(); k++ {
		seg := segs.At(k)
		b.Write(seg.Value(d.src))
	}
	return b.String()
}

func (d *mdDoc) code(info, content string, start, end int, fenced bool) {
	for l := start; l < end; l++ {
		d.excluded[l] = true
	}
	d.md.Fences = append(d.md.Fences, Fence{Info: info, Content: content, Line: start + 1 + d.off})
	d.md.CodeSpans = append(d.md.CodeSpans, d.span(start, end))
	if fenced {
		d.md.FenceSpans = append(d.md.FenceSpans, d.span(start, end))
	}
}

func (d *mdDoc) htmlBlock(b *ast.HTMLBlock) {
	start, end := d.linesSpan(b)
	if b.HasClosure() {
		end = d.lineOf(b.ClosureLine.Start) + 1
	}
	d.md.HasHTML = true
	d.inspectHTML(d.rawLines(start, end), start+1+d.off, 1)
	d.starts[start] = true
}

func (d *mdDoc) reference(b *ast.LinkReferenceDefinition) {
	label := strings.ToUpper(pytext.Lower(strings.Join(pytext.Fields(string(b.Label)), " ")))
	if d.refSeen[label] {
		return
	}
	d.refSeen[label] = true
	start, end := d.linesSpan(b)
	d.md.ReferenceSpans = append(d.md.ReferenceSpans, d.span(start, end))
}

// inline is the `inline` token of a paragraph, tight list item or heading.
func (d *mdDoc) inline(n ast.Node, topParagraph bool) {
	var start, end int
	if n.Lines().Len() == 0 { // an empty ATX heading
		bl, ok := d.blocks[n]
		if !ok {
			return
		}
		start, end = bl.open, bl.open+1
	} else {
		start, end = d.linesSpan(n)
	}
	var children []inlineTok
	d.flatten(n, &children)
	hasHTML := slices.ContainsFunc(children, func(c inlineTok) bool { return c.typ == "html_inline" })
	if !hasHTML {
		d.md.ProseSpans = append(d.md.ProseSpans, d.span(start, end))
		if topParagraph {
			d.md.ParagraphSpans = append(d.md.ParagraphSpans, d.span(start, end))
		}
		d.starts[start] = true
	}
	raw := d.rawLines(start, end)
	line := start + 1 + d.off
	if hasHTML {
		d.md.HasHTML = true
		d.inspectHTML(maskInlineCode(raw, children), line, 1)
	}
	for j, c := range children {
		switch c.typ {
		case "softbreak", "hardbreak":
			line++
		case "link_open":
			var label strings.Builder
			for k := j + 1; k < len(children) && children[k].typ != "link_close"; k++ {
				label.WriteString(children[k].content)
			}
			d.md.Links = append(d.md.Links, Link{Href: c.href, Label: label.String(), Line: line})
		}
	}
}

// inlineTok is one markdown-it inline child: text, softbreak, hardbreak, code_inline (markup =
// its backtick run), html_inline, link_open (href) / link_close, image (raw label).
type inlineTok struct{ typ, content, href, markup string }

func (d *mdDoc) flatten(n ast.Node, out *[]inlineTok) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch v := c.(type) {
		case *ast.Text:
			*out = append(*out, inlineTok{typ: "text", content: decodeText(string(v.Segment.Value(d.src)))})
			if v.HardLineBreak() {
				*out = append(*out, inlineTok{typ: "hardbreak"})
			} else if v.SoftLineBreak() {
				*out = append(*out, inlineTok{typ: "softbreak"})
			}
		case *ast.String:
			*out = append(*out, inlineTok{typ: "text", content: string(v.Value)})
		case *ast.CodeSpan:
			var content strings.Builder
			for t := v.FirstChild(); t != nil; t = t.NextSibling() {
				content.Write(t.(*ast.Text).Segment.Value(d.src))
			}
			pos := v.Pos()
			run := pos
			for run < len(d.src) && d.src[run] == '`' {
				run++
			}
			*out = append(*out, inlineTok{typ: "code_inline", markup: string(d.src[pos:run]),
				content: strings.ReplaceAll(content.String(), "\n", " ")})
		case *ast.RawHTML:
			*out = append(*out, inlineTok{typ: "html_inline", content: d.segText(v.Segments)})
		case *ast.Link:
			href := normalizeLink(unescapeAll(string(v.Destination)))
			if !validateLink(href) { // markdown-it leaves the construct as text
				d.flatten(v, out)
				continue
			}
			*out = append(*out, inlineTok{typ: "link_open", href: href})
			d.flatten(v, out)
			*out = append(*out, inlineTok{typ: "link_close"})
		case *ast.Image:
			start := v.Pos() + 2
			end := max(start, d.lastSegmentStop(v))
			if k := bytes.IndexByte(d.src[end:], ']'); k >= 0 {
				end += k
			}
			*out = append(*out, inlineTok{typ: "image", content: string(d.src[start:end])})
		case *ast.AutoLink:
			url := string(v.URL(d.src))
			if v.AutoLinkType == ast.AutoLinkEmail {
				url = "mailto:" + url
			}
			href := normalizeLink(url)
			if !validateLink(href) {
				*out = append(*out, inlineTok{typ: "text", content: string(v.Label(d.src))})
				continue
			}
			*out = append(*out, inlineTok{typ: "link_open", href: href},
				inlineTok{typ: "text", content: normalizeLinkText(string(v.Label(d.src)))},
				inlineTok{typ: "link_close"})
		default: // Emphasis and anything else with inline children
			d.flatten(c, out)
		}
	}
}

// lastSegmentStop is the byte offset just past the last source segment under n (0 when none).
func (d *mdDoc) lastSegmentStop(n ast.Node) int {
	stop := 0
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch v := c.(type) {
		case *ast.Text:
			stop = max(stop, v.Segment.Stop)
		case *ast.RawHTML:
			if v.Segments.Len() > 0 {
				stop = max(stop, v.Segments.At(v.Segments.Len()-1).Stop)
			}
		case *ast.AutoLink:
			stop = max(stop, v.Pos()+len(v.Label(d.src))+2)
		default:
			stop = max(stop, d.lastSegmentStop(c))
		}
	}
	return stop
}

// --- markdown-it text semantics: escapes, entities, link destinations ---

var (
	decodeTextRE  = regexp.MustCompile(`\\([!-/:-@\[-` + "`" + `{-~])|(?i:&#(?:x[a-f0-9]{1,6}|[0-9]{1,7});)|(?i:&[a-z][a-z0-9]{1,31};)`)
	unescapeAllRE = regexp.MustCompile(`\\([!-/:-@\[-` + "`" + `{-~])|&([a-zA-Z#][a-zA-Z0-9]{1,31});`)
	unescapeDecRE = regexp.MustCompile(`^#([0-9]{1,8})$`)
	unescapeHexRE = regexp.MustCompile(`(?i)^#x([a-f0-9]{1,8})$`)
	badProtoRE    = regexp.MustCompile(`^(vbscript|javascript|file|data):`)
	goodDataRE    = regexp.MustCompile(`^data:image/(gif|png|jpeg|webp);`)
)

// decodeText is the markdown-it escape and entity inline rules over a text run: an escaped
// ASCII punctuation loses its backslash, a numeric reference becomes its code point (U+FFFD when
// invalid), a known named entity is decoded and an unknown one is left as written.
func decodeText(s string) string {
	if !strings.ContainsAny(s, "\\&") {
		return s
	}
	return decodeTextRE.ReplaceAllStringFunc(s, func(m string) string {
		switch {
		case m[0] == '\\':
			return m[1:]
		case m[1] == '#':
			digits, base := m[2:len(m)-1], 10
			if digits[0] == 'x' || digits[0] == 'X' {
				digits, base = digits[1:], 16
			}
			if r, ok := codePoint(digits, base); ok {
				return string(r)
			}
			return "\ufffd"
		}
		return html.UnescapeString(m)
	})
}

// codePoint parses a numeric character reference of at most 8 digits (the regexes cap the run);
// ok is markdown-it's isValidEntityCode.
func codePoint(digits string, base int) (rune, bool) {
	c, _ := strconv.ParseInt(digits, base, 64)
	return rune(c), validEntityCode(c)
}

func validEntityCode(c int64) bool {
	switch {
	case c >= 0xD800 && c <= 0xDFFF, c >= 0xFDD0 && c <= 0xFDEF, c&0xFFFF == 0xFFFF, c&0xFFFF == 0xFFFE,
		c <= 0x08, c == 0x0B, c >= 0x0E && c <= 0x1F, c >= 0x7F && c <= 0x9F, c > 0x10FFFF:
		return false
	}
	return true
}

// unescapeAll is markdown-it's common.utils.unescapeAll (link destinations).
func unescapeAll(s string) string {
	if !strings.ContainsAny(s, "\\&") {
		return s
	}
	return unescapeAllRE.ReplaceAllStringFunc(s, func(m string) string {
		if m[0] == '\\' {
			return m[1:]
		}
		name := m[1 : len(m)-1]
		if name[0] == '#' {
			var r rune
			ok := false
			if n := unescapeDecRE.FindStringSubmatch(name); n != nil {
				r, ok = codePoint(n[1], 10)
			} else if n := unescapeHexRE.FindStringSubmatch(name); n != nil {
				r, ok = codePoint(n[1], 16)
			}
			if ok {
				return string(r)
			}
			return m
		}
		return html.UnescapeString(m)
	})
}

// validateLink is markdown-it's validateLink.
func validateLink(u string) bool {
	u = strings.ToLower(pytext.Strip(u))
	return !badProtoRE.MatchString(u) || goodDataRE.MatchString(u)
}

// --- mdurl (markdown-it's URL normaliser): parse, format, encode, decode ---

type mdURL struct {
	protocol, auth, port, hostname, hash, search, pathname string
	slashes                                                bool
}

var (
	protocolRE      = regexp.MustCompile(`(?i)^([a-z0-9.+-]+:)`)
	portRE          = regexp.MustCompile(`:[0-9]*$`)
	hostPartRE      = regexp.MustCompile(`^[+a-z0-9A-Z_-]{0,63}$`)
	hostPartStartRE = regexp.MustCompile(`^([+a-z0-9A-Z_-]{0,63})(.*)$`)
	hostlessProto   = map[string]bool{"javascript:": true}
	slashedProto    = map[string]bool{"http:": true, "https:": true, "ftp:": true, "gopher:": true, "file:": true}
	nonHostChars    = "%/?;#'{}|\\^`<>\"` \r\n\t"
	encodeExclude   = ";/?:@&=+$,-_.!~*'()#"
	decodeExclude   = ";/?:@&=+$,#%"
	percentSeqRE    = regexp.MustCompile(`(?i)(%[a-f0-9]{2})+`)
	recodeHostnames = map[string]bool{"http:": true, "https:": true, "mailto:": true}
)

// parseURL is mdurl.parse(url, slashes_denote_host=True).
func parseURL(u string) mdURL {
	var r mdURL
	rest := pytext.Strip(u)
	proto := protocolRE.FindString(rest)
	if proto != "" {
		r.protocol = proto
		rest = rest[len(proto):]
	}
	slashes := strings.HasPrefix(rest, "//")
	if slashes && !(proto != "" && hostlessProto[proto]) {
		rest = rest[2:]
		r.slashes = true
	}
	if !hostlessProto[proto] && (slashes || (proto != "" && !slashedProto[proto])) {
		hostEnd := strings.IndexAny(rest, "/?#")
		var atSign int
		if hostEnd == -1 {
			atSign = strings.LastIndex(rest, "@")
		} else {
			atSign = strings.LastIndex(rest[:hostEnd+1], "@")
		}
		if atSign != -1 {
			r.auth = rest[:atSign]
			rest = rest[atSign+1:]
		}
		hostEnd = strings.IndexAny(rest, nonHostChars)
		if hostEnd == -1 {
			hostEnd = len(rest)
		}
		if hostEnd > 0 && rest[hostEnd-1] == ':' {
			hostEnd--
		}
		host := rest[:hostEnd]
		rest = rest[hostEnd:]
		if m := portRE.FindString(host); m != "" {
			if m != ":" {
				r.port = m[1:]
			}
			host = host[:len(host)-len(m)]
		}
		r.hostname = host
		ipv6 := strings.HasPrefix(r.hostname, "[") && strings.HasSuffix(r.hostname, "]")
		if !ipv6 {
			parts := strings.Split(r.hostname, ".")
			for i, part := range parts {
				if part == "" || hostPartRE.MatchString(part) {
					continue
				}
				ascii := strings.Map(func(c rune) rune {
					if c > 127 {
						return 'x'
					}
					return c
				}, part)
				if hostPartRE.MatchString(ascii) {
					continue
				}
				valid := append([]string{}, parts[:i]...)
				notHost := append([]string{}, parts[i+1:]...)
				if bit := hostPartStartRE.FindStringSubmatch(part); bit != nil {
					valid = append(valid, bit[1])
					notHost = append([]string{bit[2]}, notHost...)
				}
				if len(notHost) > 0 {
					rest = strings.Join(notHost, ".") + rest
				}
				r.hostname = strings.Join(valid, ".")
				break
			}
		}
		if utf8.RuneCountInString(r.hostname) > 255 {
			r.hostname = ""
		}
		if ipv6 {
			r.hostname = r.hostname[1 : len(r.hostname)-1]
		}
	}
	if i := strings.IndexByte(rest, '#'); i != -1 {
		r.hash, rest = rest[i:], rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i != -1 {
		r.search, rest = rest[i:], rest[:i]
	}
	r.pathname = rest
	return r
}

// format is mdurl.format.
func (r mdURL) format() string {
	var b strings.Builder
	b.WriteString(r.protocol)
	if r.slashes {
		b.WriteString("//")
	}
	if r.auth != "" {
		b.WriteString(r.auth + "@")
	}
	if strings.Contains(r.hostname, ":") {
		b.WriteString("[" + r.hostname + "]")
	} else {
		b.WriteString(r.hostname)
	}
	if r.port != "" {
		b.WriteString(":" + r.port)
	}
	b.WriteString(r.pathname + r.search + r.hash)
	return b.String()
}

// encodeURL is mdurl.encode with keep_escaped: percent-encode every byte but ASCII alphanumerics,
// the exclude set and well-formed %XX sequences (the text is valid UTF-8, so the bytes >= 0x80 are
// exactly the encoding of its non-ASCII code points).
func encodeURL(s string, exclude string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteString(s[i : i+3])
			i += 2
		case c < 128 && (isAlnum(c) || strings.IndexByte(exclude, c) >= 0):
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// decodeURL is mdurl.decode: percent sequences become their UTF-8 text except the excluded
// ASCII characters (re-emitted upper-case) and malformed sequences (U+FFFD per byte).
func decodeURL(s string, exclude string) string {
	return percentSeqRE.ReplaceAllStringFunc(s, func(seq string) string {
		var b strings.Builder
		for i := 0; i < len(seq); {
			b1 := hexByte(seq[i+1 : i+3])
			if b1 < 0x80 {
				if strings.IndexByte(exclude, b1) >= 0 {
					fmt.Fprintf(&b, "%%%02X", b1)
				} else {
					b.WriteByte(b1)
				}
				i += 3
				continue
			}
			n := 0
			switch {
			case b1&0xE0 == 0xC0:
				n = 2
			case b1&0xF0 == 0xE0:
				n = 3
			case b1&0xF8 == 0xF0:
				n = 4
			}
			if n > 1 && i+3*n <= len(seq) {
				raw := make([]byte, 0, n)
				for k := range n {
					raw = append(raw, hexByte(seq[i+3*k+1:i+3*k+3]))
				}
				ok := true
				for _, x := range raw[1:] {
					ok = ok && x&0xC0 == 0x80
				}
				if ok {
					if utf8.Valid(raw) {
						b.Write(raw)
					} else {
						b.WriteString(strings.Repeat("�", n))
					}
					i += 3 * n
					continue
				}
			}
			b.WriteString("�")
			i += 3
		}
		return b.String()
	})
}

// hexByte parses two hex digits (percentSeqRE guarantees the shape).
func hexByte(s string) byte { v, _ := strconv.ParseUint(s, 16, 8); return byte(v) }

// normalizeLink is markdown-it's normalizeLink: punycode the hostname of http/https/mailto and
// schemeless URLs, then percent-encode.
func normalizeLink(u string) string {
	p := parseURL(u)
	if p.hostname != "" && (p.protocol == "" || recodeHostnames[p.protocol]) {
		if h, err := idna.Punycode.ToASCII(p.hostname); err == nil {
			p.hostname = h
		}
	}
	return encodeURL(p.format(), encodeExclude)
}

// normalizeLinkText is markdown-it's normalizeLinkText (autolink label).
func normalizeLinkText(u string) string {
	p := parseURL(u)
	if p.hostname != "" && (p.protocol == "" || recodeHostnames[p.protocol]) {
		if h, err := idna.Punycode.ToUnicode(p.hostname); err == nil {
			p.hostname = h
		}
	}
	return decodeURL(p.format(), decodeExclude)
}

// --- _mask_inline_code ---

// runeIndex is str.find on code points.
func runeIndex(hay, needle []rune, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i+len(needle) <= len(hay); i++ {
		match := true
		for k := range needle {
			if hay[i+k] != needle[k] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// maskInlineCode blanks every code span of an inline token in its raw source so the HTML
// inspection never sees tags quoted inside backticks (parse._mask_inline_code).
func maskInlineCode(source string, children []inlineTok) string {
	masked := []rune(source)
	cursor := 0
	for _, c := range children {
		if c.typ != "code_inline" {
			continue
		}
		marker := []rune(c.markup)
		if len(marker) == 0 {
			marker = []rune{'`'}
		}
		needle := append(append(append([]rune{}, marker...), []rune(c.content)...), marker...)
		start := runeIndex(masked, needle, cursor)
		var end int
		if start < 0 {
			start = runeIndex(masked, marker, cursor)
			end = -1
			if start >= 0 {
				end = runeIndex(masked, marker, start+len(marker))
			}
		} else {
			end = start + len(needle) - len(marker)
		}
		if start < 0 || end < 0 {
			continue
		}
		stop := end + len(marker)
		for i := start; i < stop; i++ {
			if masked[i] != '\n' {
				masked[i] = ' '
			}
		}
		cursor = stop
	}
	return string(masked)
}

// --- HTML inspection (_InspectableHTML over x/net/html, with html.parser's edge semantics) ---

var presentationalHTML = map[string]bool{
	"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true, "blockquote": true, "br": true, "caption": true,
	"cite": true, "code": true, "col": true, "colgroup": true, "dd": true, "del": true, "details": true, "dfn": true,
	"div": true, "dl": true, "dt": true, "em": true, "figcaption": true, "figure": true, "h1": true, "h2": true,
	"h3": true, "h4": true, "h5": true, "h6": true, "hr": true, "i": true, "img": true, "ins": true, "kbd": true,
	"li": true, "mark": true, "ol": true, "p": true, "picture": true, "pre": true, "q": true, "rp": true, "rt": true,
	"ruby": true, "s": true, "samp": true, "small": true, "source": true, "span": true, "strong": true, "sub": true,
	"summary": true, "sup": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true, "thead": true,
	"time": true, "tr": true, "u": true, "ul": true, "var": true, "wbr": true,
}

var globalHTMLAttrs = map[string]bool{"class": true, "dir": true, "id": true, "lang": true, "role": true, "title": true}

// urlHTMLAttrs are the modelled attributes whose value is a URL.
var urlHTMLAttrs = map[string]bool{"href": true, "src": true, "cite": true}

// urlNamedHTMLAttrs name a reference wherever they appear; on a tag outside the modelled set the
// reference is content the link model never saw, whatever form the value takes.
var urlNamedHTMLAttrs = map[string]bool{"href": true, "src": true, "srcset": true, "data": true, "poster": true,
	"action": true, "formaction": true, "cite": true, "background": true, "longdesc": true, "xlink:href": true, "ping": true}

var tagHTMLAttrs = map[string]map[string]bool{
	"a":          {"href": true, "rel": true, "target": true},
	"blockquote": {"cite": true}, "q": {"cite": true},
	"col": {"span": true}, "colgroup": {"span": true},
	"details": {"open": true},
	"img":     {"alt": true, "height": true, "loading": true, "src": true, "width": true},
	"source":  {"height": true, "media": true, "src": true, "type": true, "width": true},
	"td":      {"colspan": true, "headers": true, "rowspan": true},
	"th":      {"abbr": true, "colspan": true, "headers": true, "rowspan": true, "scope": true},
	"time":    {"datetime": true},
}

var (
	lowerSchemeRE   = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:`)
	schemePayloadRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:\S`)                           // a scheme with its payload; a CSS `name: value` is not one
	commentCloseRE  = regexp.MustCompile(`--` + pytext.Space + `*>`)                        // _markupbase._commentclose
	markedCloseRE   = regexp.MustCompile(`\]` + pytext.Space + `*\]` + pytext.Space + `*>`) // _markedsectionclose
	msMarkedRE      = regexp.MustCompile(`\]` + pytext.Space + `*>`)                        // _msmarkedsectionclose
	declNameRE      = regexp.MustCompile(`^[a-zA-Z][-_.a-zA-Z0-9]*`)
)

// htmlCrash marks input on which Python raises past parse_markdown (html.parser's
// AssertionError); the panic surfaces as the artifact's parse_crash diagnostic, recorded by its
// type only, so msg documents the Python exception and is never read.
type htmlCrash struct{ msg string }

type htmlAnchor struct {
	target string
	label  []string
	line   int
}

type htmlInspector struct {
	d            *mdDoc
	frag         string
	fragLines    []int
	line, column int
	fully, saw   bool
	unknown      bool // a tag or attribute outside the presentational set
	text         bool // a text token that is not whitespace
	anchors      []*htmlAnchor
	codeStack    []string
}

// inspectHTML is parse._inspect_html, graded by what the fragment hid (HTMLHidesContent) rather
// than by one uninspectable state.
func (d *mdDoc) inspectHTML(fragment string, line, column int) {
	h := &htmlInspector{d: d, frag: fragment, line: line, column: column, fully: true}
	h.fragLines = []int{0}
	for i := 0; i < len(fragment); i++ {
		if fragment[i] == '\n' {
			h.fragLines = append(h.fragLines, i+1)
		}
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if c, ok := r.(htmlCrash); ok {
					panic(c)
				}
				h.fully = false
			}
		}()
		h.run()
	}()
	if len(h.anchors) > 0 || len(h.codeStack) > 0 {
		h.fully = false
	}
	if !h.saw || !h.fully || h.unknown {
		d.md.HasUninspectableHTML = true
		d.md.HTMLHidesContent = d.md.HTMLHidesContent || !h.saw || !h.fully || h.text
		d.md.HTMLUninspectable = append(d.md.HTMLUninspectable, HTMLFragment{Text: fragment, Line: line, Column: column})
	} else {
		d.md.HTMLProse = append(d.md.HTMLProse, HTMLProse{Text: projectHTML(fragment), Line: line})
	}
}

// run tokenizes the fragment. Where html.parser and x/net/html disagree on where a construct
// ends (comments close at `--\s*>`, marked sections at `]\s*]\s*>`, unterminated markup at end
// of input becomes text up to the next `>` or `<`), the tokenizer is restarted at Python's
// position.
func (h *htmlInspector) run() {
	for pos := 0; pos < len(h.frag); {
		z := xhtml.NewTokenizer(strings.NewReader(h.frag[pos:]))
		z.AllowCDATA(false)
		off := pos
		restart := -1
		for restart < 0 {
			tt := z.Next()
			if tt == xhtml.ErrorToken {
				if off < len(h.frag) { // unterminated markup at end of input
					restart = h.fallback(off)
				} else {
					restart = len(h.frag)
				}
				break
			}
			raw := string(z.Raw())
			start := off
			off += len(raw)
			switch tt {
			case xhtml.TextToken:
				h.data(z.Token().Data)
			case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
				tok := z.Token()
				attrs, ok := pyStartTagAttrs(raw)
				if !ok { // html.parser reports a tag whose tail is not `>` or `/>` as data
					h.data(raw)
					continue
				}
				h.startTag(tok.Data, attrs, start)
				if tt == xhtml.SelfClosingTagToken {
					h.selfClose(tok.Data)
				}
			case xhtml.EndTagToken:
				h.endTag(z.Token().Data, start)
			case xhtml.DoctypeToken:
				if !strings.HasSuffix(raw, ">") {
					restart = h.fallback(start)
					break
				}
				h.saw, h.fully = true, false
			case xhtml.CommentToken:
				restart = h.comment(raw, start, off)
			}
		}
		pos = restart
	}
}

// comment dispatches x/net's CommentToken (comments, declarations, bogus comments, processing
// instructions) the way html.parser does; it returns the position to resume from, or -1 to
// keep the current tokenizer.
func (h *htmlInspector) comment(raw string, start, end int) int {
	switch {
	case raw == "</>":
		return -1
	case strings.HasPrefix(raw, "<!--"):
		m := commentCloseRE.FindStringIndex(h.frag[start+4:])
		if m == nil {
			return h.fallback(start)
		}
		h.saw = true
		l, col := h.pos(start)
		h.d.md.HTMLComments = append(h.d.md.HTMLComments, HTMLComment{Body: h.frag[start+4 : start+4+m[0]], Line: h.line + l - 1, Column: h.sourceColumn(l, col)})
		return h.resume(start+4+m[1], end)
	case strings.HasPrefix(raw, "<!["):
		rest := h.frag[start+3:]
		if rest == "" {
			return h.fallback(start)
		}
		name := declNameRE.FindString(rest)
		if name == "" {
			panic(htmlCrash{"expected name token"})
		}
		closer := msMarkedRE
		switch strings.ToLower(name) {
		case "temp", "cdata", "ignore", "include", "rcdata":
			closer = markedCloseRE
		case "if", "else", "endif":
		default:
			panic(htmlCrash{"unknown status keyword in marked section"})
		}
		m := closer.FindStringIndex(rest)
		if m == nil {
			return h.fallback(start)
		}
		h.saw, h.fully = true, false
		return h.resume(start+3+m[1], end)
	default: // <?pi>, <!bogus>, </ bogus>
		if !strings.HasSuffix(raw, ">") {
			return h.fallback(start)
		}
		h.saw = true
		if strings.HasPrefix(raw, "<?") {
			h.fully = false
			return -1
		}
		l, col := h.pos(start)
		h.d.md.HTMLComments = append(h.d.md.HTMLComments, HTMLComment{Body: raw[2 : len(raw)-1], Line: h.line + l - 1, Column: h.sourceColumn(l, col)})
		return -1
	}
}

func (h *htmlInspector) resume(pyEnd, goEnd int) int {
	if pyEnd == goEnd {
		return -1
	}
	return pyEnd
}

// fallback is HTMLParser.goahead(end=True) on markup it could not terminate: the text up to and
// including the next `>`, else up to the next `<`, else one character, is data.
func (h *htmlInspector) fallback(i int) int {
	k := strings.IndexByte(h.frag[i+1:], '>')
	if k >= 0 {
		k += i + 2
	} else if k = strings.IndexByte(h.frag[i+1:], '<'); k >= 0 {
		k += i + 1
	} else {
		k = i + 1
	}
	h.data(html.UnescapeString(h.frag[i:k]))
	return k
}

// pos is HTMLParser.getpos for byte offset start: 1-based fragment line and 0-based code-point column.
func (h *htmlInspector) pos(start int) (int, int) {
	l := sort.SearchInts(h.fragLines, start+1) - 1
	return l + 1, utf8.RuneCountInString(h.frag[h.fragLines[l]:start])
}

func (h *htmlInspector) sourceColumn(l, col int) int {
	if l == 1 {
		return col + h.column
	}
	return col + 1
}

func (h *htmlInspector) data(s string) {
	if strings.TrimSpace(s) != "" {
		h.text = true
	}
	for _, a := range h.anchors {
		a.label = append(a.label, s)
	}
}

// pyStartTagAttrs is html.parser's parse_starttag attribute scan (tagfind_tolerant then
// attrfind_tolerant) over the raw tag: every attribute is kept, duplicates included, with
// lower-cased names and unquoted, unescaped values ("" when absent). x/net's tokenizer drops
// repeated names, which Python treats as uninspectable and resolves last-wins for href/src. ok
// is false when the tail before `>` is not empty or `/`.
func pyStartTagAttrs(raw string) (attrs [][2]string, ok bool) {
	rs := []rune(raw)
	i := 1
	for i < len(rs) && !strings.ContainsRune("\t\n\r\f />\x00", rs[i]) {
		i++
	}
	skip := func() {
		for i < len(rs) && (pytext.IsSpace(rs[i]) || (rs[i] == '/' && !(i+1 < len(rs) && rs[i+1] == '>'))) {
			i++
		}
	}
	skip()
	attrs = [][2]string{}
	for i < len(rs) && !pytext.IsSpace(rs[i]) && rs[i] != '/' && rs[i] != '>' {
		start := i
		for i++; i < len(rs) && !pytext.IsSpace(rs[i]) && rs[i] != '/' && rs[i] != '=' && rs[i] != '>'; i++ {
		}
		name := strings.ToLower(string(rs[start:i]))
		value := ""
		j := i
		for j < len(rs) && pytext.IsSpace(rs[j]) {
			j++
		}
		if j < len(rs) && rs[j] == '=' {
			for j < len(rs) && rs[j] == '=' {
				j++
			}
			for j < len(rs) && pytext.IsSpace(rs[j]) {
				j++
			}
			k := j
			if j < len(rs) && (rs[j] == '\'' || rs[j] == '"') {
				for k++; k < len(rs) && rs[k] != rs[j]; k++ {
				}
				value = string(rs[j+1 : min(k, len(rs))])
				k = min(k+1, len(rs))
			} else {
				for k < len(rs) && rs[k] != '>' && !pytext.IsSpace(rs[k]) {
					k++
				}
				value = string(rs[j:k])
			}
			i = k
			if value != "" {
				value = html.UnescapeString(value)
			}
		}
		attrs = append(attrs, [2]string{name, value})
		skip()
	}
	tail := pytext.Strip(string(rs[i:]))
	return attrs, tail == ">" || tail == "/>"
}

func (h *htmlInspector) startTag(tag string, norm [][2]string, start int) {
	h.saw = true
	tag = strings.ToLower(tag)
	l, col := h.pos(start)
	line := h.line + l - 1
	values := map[string]string{} // last wins, as html.parser's attribute lookup
	for _, a := range norm {
		values[a[0]] = a[1]
	}
	h.d.md.HTMLTags = append(h.d.md.HTMLTags, HTMLTag{Name: tag, Line: line, Column: h.sourceColumn(l, col), Attrs: norm})
	if len(values) != len(norm) { // a repeated attribute name
		h.fully = false
	}
	known := presentationalHTML[tag] || tag == "subject"
	if !known {
		h.unknown = true
	}
	for _, a := range norm {
		switch {
		case known && (globalHTMLAttrs[a[0]] || tagHTMLAttrs[tag][a[0]]):
			if urlHTMLAttrs[a[0]] && activeScheme(a[1]) {
				h.fully = false
			}
		case strings.HasPrefix(a[0], "on") || activeScheme(a[1]):
			h.fully = false // an event handler or an active scheme is executable content
		default:
			h.unknown = true
			if (!known && urlNamedHTMLAttrs[a[0]]) || (a[0] == "style" && styleCarriesContent(a[1])) || (a[0] != "style" && attrCarriesContent(a[1])) {
				h.text = true // a reference or words the prose and link models never saw
			}
		}
	}
	if !known {
		return
	}
	if tag == "code" || tag == "pre" {
		h.codeStack = append(h.codeStack, tag)
	}
	target := values["src"]
	if tag == "a" {
		target = values["href"]
	}
	if target == "" {
		return
	}
	compact := compactURL(target)
	if (tag == "img" || tag == "source") && (strings.HasPrefix(compact, "//") || lowerSchemeRE.MatchString(compact)) {
		h.fully = false
	}
	if tag == "a" {
		h.anchors = append(h.anchors, &htmlAnchor{target: target, line: line})
	}
}

// compactURL lowers a URL and drops the control and space characters a browser ignores.
func compactURL(s string) string {
	return pytext.Lower(strings.Map(func(r rune) rune {
		if r <= 0x20 {
			return -1
		}
		return r
	}, s))
}

// activeScheme reports a data, javascript or vbscript URL among the comma-separated candidates
// of a value: srcset names several, and a later one hides as well as the first.
func activeScheme(s string) bool {
	for _, c := range strings.Split(s, ",") {
		compact := compactURL(c)
		i := strings.IndexByte(compact, ':')
		if i >= 0 && (compact[:i] == "data" || compact[:i] == "javascript" || compact[:i] == "vbscript") {
			return true
		}
	}
	return false
}

// attrCarriesContent reports a value outside the modelled set that is more than a layout token:
// a URL among its comma-separated candidates, or at least two words of letters, whatever
// punctuation surrounds them.
func attrCarriesContent(v string) bool {
	for _, c := range strings.Split(v, ",") {
		compact := compactURL(c)
		if strings.Contains(compact, "://") || strings.HasPrefix(compact, "//") || schemePayloadRE.MatchString(pytext.Lower(strings.TrimSpace(c))) {
			return true
		}
	}
	words := 0
	for _, f := range strings.Fields(v) {
		f = strings.TrimFunc(f, unicode.IsPunct) // sentence punctuation around a word; a digit still makes it a token
		if utf8.RuneCountInString(f) >= 2 && strings.IndexFunc(f, func(r rune) bool { return !unicode.IsLetter(r) }) < 0 {
			words++
		}
	}
	return words >= 2
}

// styleCarriesContent reads a style attribute as CSS: a URL in a declaration's value, or two
// words of letters there, is content; a property name such as display or width is not, with or
// without a space after its colon.
func styleCarriesContent(v string) bool {
	for _, decl := range strings.Split(v, ";") {
		name, value, ok := strings.Cut(decl, ":")
		if !ok {
			value = name // no property at all: the whole declaration is the value
		}
		if attrCarriesContent(value) {
			return true
		}
	}
	return false
}

func (h *htmlInspector) popAnchor() {
	a := h.anchors[len(h.anchors)-1]
	h.anchors = h.anchors[:len(h.anchors)-1]
	h.d.md.Links = append(h.d.md.Links, Link{Href: a.target, Label: pytext.Strip(strings.Join(a.label, "")), Line: a.line})
}

func (h *htmlInspector) selfClose(tag string) {
	tag = strings.ToLower(tag)
	if (tag == "code" || tag == "pre") && len(h.codeStack) > 0 {
		h.codeStack = h.codeStack[:len(h.codeStack)-1]
	}
	if tag == "a" && len(h.anchors) > 0 {
		h.popAnchor()
	}
}

func (h *htmlInspector) endTag(tag string, start int) {
	h.saw = true
	tag = strings.ToLower(tag)
	l, col := h.pos(start)
	h.d.md.HTMLTags = append(h.d.md.HTMLTags, HTMLTag{Name: tag, Line: h.line + l - 1, Column: h.sourceColumn(l, col), Closing: true})
	if !presentationalHTML[tag] && tag != "subject" {
		h.unknown = true
	}
	if tag == "code" || tag == "pre" {
		if len(h.codeStack) == 0 || h.codeStack[len(h.codeStack)-1] != tag {
			h.fully = false
		} else {
			h.codeStack = h.codeStack[:len(h.codeStack)-1]
		}
	}
	if tag == "a" && len(h.anchors) > 0 {
		h.popAnchor()
	}
}

// --- _project_html ---

var (
	htmlProjectionTokenRE = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)|<(?:[^>"']|"[^"]*"|'[^']*')*>|&(?:#[xX][0-9A-Fa-f]+;?|#\p{Nd}+;?|[A-Za-z][A-Za-z0-9]+;)`)
	htmlProjectionTagRE   = regexp.MustCompile(`(?is)^<` + pytext.Space + `*(/?)` + pytext.Space + `*([a-z][a-z0-9-]*)`)
)

// projectHTML is parse._project_html: the rendered prose with source width and newlines kept.
func projectHTML(fragment string) string {
	var out strings.Builder
	pos, depth := 0, 0
	for _, m := range htmlProjectionTokenRE.FindAllStringIndex(fragment, -1) {
		txt := fragment[pos:m[0]]
		if depth > 0 {
			txt = pytext.BlankKeepNewlines(txt)
		}
		out.WriteString(txt)
		token := fragment[m[0]:m[1]]
		switch {
		case strings.HasPrefix(token, "<") && !strings.HasPrefix(token, "<!--"):
			if tm := htmlProjectionTagRE.FindStringSubmatch(token); tm != nil {
				if name := strings.ToLower(tm[2]); name == "code" || name == "pre" {
					switch {
					case tm[1] != "":
						depth--
					case strings.HasSuffix(pytext.RStrip(token), "/>"):
					default:
						depth++
					}
					depth = max(depth, 0)
				}
			}
			out.WriteString(pytext.BlankKeepNewlines(token))
		case strings.HasPrefix(token, "&") && depth == 0:
			decoded := strings.NewReplacer("\r", " ", "\n", " ").Replace(html.UnescapeString(token))
			width := utf8.RuneCountInString(token)
			padded := []rune(decoded + strings.Repeat(" ", width))
			out.WriteString(string(padded[:width]))
		default:
			out.WriteString(pytext.BlankKeepNewlines(token))
		}
		pos = m[1]
	}
	tail := fragment[pos:]
	if depth > 0 {
		tail = pytext.BlankKeepNewlines(tail)
	}
	out.WriteString(tail)
	return out.String()
}

// --- line-based helpers after the parse: table exclusion and the inline scan ---

var (
	tableDividerRE = regexp.MustCompile(`^` + pytext.Space + `*\|?` + pytext.Space + `*:?-{3,}:?(?:` + pytext.Space + `*\|` + pytext.Space + `*:?-{3,}:?)*` + pytext.Space + `*\|?` + pytext.Space + `*$`)
	blockOpenerRE  = regexp.MustCompile("^ {0,3}(?:#{1,6}(?:[ \t]|$)|`{3,}|~{3,}|(?:[-+*]|\\p{Nd}+[.)])[ \t]+)")
	listItemRE     = regexp.MustCompile(`^( {0,3})(?:[-+*]|\p{Nd}+[.)])([ \t]+)`)
)

func isBlank(rs []rune) bool {
	return !slices.ContainsFunc(rs, func(r rune) bool { return !pytext.IsSpace(r) })
}

func leadingSpaces(rs []rune) int {
	n := 0
	for n < len(rs) && rs[n] == ' ' {
		n++
	}
	return n
}

func toRunes(lines []string) [][]rune {
	out := make([][]rune, len(lines))
	for i, l := range lines {
		out[i] = []rune(l)
	}
	return out
}

// blockquoteParts is parse._blockquote_parts: the content after the `>` markers, its
// code-point offset and the marker depth.
func blockquoteParts(line []rune) (content []rune, prefix, depth int) {
	pos := 0
	for pos < len(line) {
		segStart := pos
		for spaces := 0; pos < len(line) && line[pos] == ' ' && spaces < 3; spaces++ {
			pos++
		}
		if pos >= len(line) || line[pos] != '>' {
			if depth == 0 {
				return line, 0, 0
			}
			return line[segStart:], segStart, depth
		}
		depth++
		pos++
		if pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
			pos++
		}
	}
	return line[pos:], pos, depth
}

// container is the (blockquote depth, list indent) identity of a line.
type container struct{ depth, listIndent int }

type containerLine struct {
	content []rune
	prefix  int
	container
}

// containerLines is parse._container_lines.
func containerLines(lines [][]rune) []containerLine {
	listIndents := map[int]int{}
	out := make([]containerLine, 0, len(lines))
	for _, source := range lines {
		content, prefix, depth := blockquoteParts(source)
		if isBlank(content) {
			out = append(out, containerLine{content, prefix, container{depth, listIndents[depth]}})
			continue
		}
		if m := listItemRE.FindStringIndex(string(content)); m != nil {
			indent := utf8.RuneCountInString(string(content)[:m[1]])
			listIndents[depth] = indent
			out = append(out, containerLine{content[indent:], prefix + indent, container{depth, indent}})
			continue
		}
		indent, ok := listIndents[depth]
		leading := leadingSpaces(content)
		if ok && leading >= indent {
			out = append(out, containerLine{content[indent:], prefix + indent, container{depth, indent}})
			continue
		}
		if leading == 0 {
			delete(listIndents, depth)
		}
		out = append(out, containerLine{content, prefix, container{depth, 0}})
	}
	return out
}

// tableSeparators is parse._table_separators: `|` positions outside backtick code spans.
func tableSeparators(line []rune) []int {
	var seps []int
	codeWidth := -1
	for i := 0; i < len(line); {
		switch line[i] {
		case '\\':
			i += 2
			continue
		case '`':
			end := i + 1
			for end < len(line) && line[end] == '`' {
				end++
			}
			if width := end - i; codeWidth < 0 {
				codeWidth = width
			} else if codeWidth == width {
				codeWidth = -1
			}
			i = end
			continue
		case '|':
			if codeWidth < 0 {
				seps = append(seps, i)
			}
		}
		i++
	}
	return seps
}

func tableCellCount(line []rune) int {
	seps := tableSeparators(line)
	if len(seps) == 0 {
		return 0
	}
	first := 0
	for first < len(line) && pytext.IsSpace(line[first]) {
		first++
	}
	last := len(line) - 1
	for last >= 0 && pytext.IsSpace(line[last]) {
		last--
	}
	n := len(seps) + 1
	if seps[0] == first {
		n--
	}
	if seps[len(seps)-1] == last {
		n--
	}
	return n
}

// tableLines is parse._table_lines: the 0-based lines of every GFM-shaped table.
func tableLines(lines [][]rune) map[int]bool {
	table := map[int]bool{}
	prepared := containerLines(lines)
	for index := 1; index < len(lines); {
		line, header := prepared[index], prepared[index-1]
		if !tableDividerRE.MatchString(string(line.content)) || tableCellCount(line.content) == 0 ||
			tableCellCount(line.content) != tableCellCount(header.content) || line.container != header.container {
			index++
			continue
		}
		end := index
		for end+1 < len(lines) {
			c := prepared[end+1]
			if c.container != line.container || blockOpenerRE.MatchString(string(c.content)) || tableCellCount(c.content) == 0 {
				break
			}
			end++
		}
		for l := index - 1; l <= end; l++ {
			table[l] = true
		}
		index = end + 1
	}
	return table
}

// scanInlinePreproc is parse._scan_inline_preproc on the parsed path: the linear !`cmd` scan
// outside the excluded lines (fences and indented code), multi-backtick spans and, with
// markdownExclusions, GFM tables; blockStarts are the lines that open a new code-span scope.
func scanInlinePreproc(text string, lineOffset int, excluded map[int]bool, markdownExclusions bool, blockStarts map[int]bool) ([]Preproc, int) {
	lines := toRunes(strings.Split(text, "\n"))
	table := map[int]bool{}
	if markdownExclusions {
		table = tableLines(lines)
	}
	blockIDs := make([]int, len(lines)) // 0 == None
	block := 0
	for index, source := range lines {
		if blockStarts[index] {
			block++
		}
		if isBlank(source) || table[index] || excluded[index] {
			block++
			continue
		}
		blockIDs[index] = block + 1
	}
	remaining := map[[2]int]int{} // (block, backtick-run width) -> runs not yet passed
	for index, source := range lines {
		id := blockIDs[index]
		if id == 0 {
			continue
		}
		for i := 0; i < len(source); {
			if source[i] != '`' {
				i++
				continue
			}
			end := i + 1
			for end < len(source) && source[end] == '`' {
				end++
			}
			if end-i >= 2 {
				remaining[[2]int{id, end - i}]++
			}
			i = end
		}
	}
	var tokens []Preproc
	total, decoys := 0, 0
	inlineTicks, activeBlock := 0, 0
	for lineIndex, source := range lines {
		id := blockIDs[lineIndex]
		if id == 0 {
			inlineTicks, activeBlock = 0, 0
			continue
		}
		if id != activeBlock {
			inlineTicks, activeBlock = 0, id
		}
		for pos := 0; pos < len(source); {
			if markdownExclusions && source[pos] == '`' {
				end := pos + 1
				for end < len(source) && source[end] == '`' {
					end++
				}
				if width := end - pos; width >= 2 {
					key := [2]int{id, width}
					remaining[key]--
					if inlineTicks == 0 {
						if remaining[key] > 0 {
							inlineTicks = width
						}
					} else if inlineTicks == width {
						inlineTicks = 0
					}
				}
				pos = end
				continue
			}
			if inlineTicks == 0 && source[pos] == '!' && pos+2 < len(source) && source[pos+1] == '`' && source[pos+2] != '`' {
				end := runeIndex(source, []rune{'`'}, pos+2)
				if end > pos+2 && (end+1 == len(source) || source[end+1] != '`') {
					command := string(source[pos+2 : end])
					if pytext.Strip(command) == "" {
						pos = end + 1
						continue
					}
					runs := pos == 0 || pytext.IsSpace(source[pos-1])
					if runs {
						total++
					} else {
						decoys++
					}
					if (runs && total <= MaxPreprocTokens) || (!runs && decoys <= MaxPreprocTokens) {
						tokens = append(tokens, Preproc{Kind: "inline", Code: command, Line: lineIndex + 1 + lineOffset, Runs: runs, Column: pos + 1})
					}
					pos = end + 1
					continue
				}
			}
			pos++
		}
	}
	return tokens, total
}
