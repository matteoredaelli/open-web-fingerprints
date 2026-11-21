// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package opentechalyzer

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file reads the subset of TypeScript in which OpenTechalyzer writes its
// fingerprints: `export const NAME: Type = <literal>;` where the literal is
// made of objects, arrays, strings (with `+` concatenation), numbers,
// booleans and null. Nothing is executed or evaluated; anything else is an
// error, so a file that uses code cannot be half-read.

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tNumber
	tPunct
)

type token struct {
	kind tokKind
	text string // identifier, decoded string, number literal or the punctuation character
	pos  int    // byte offset, for errors
}

type lexer struct {
	src  string
	pos  int
	toks []token
}

func lex(src string) ([]token, error) {
	l := &lexer{src: src}
	for {
		l.skipSpace()
		if l.pos >= len(l.src) {
			l.toks = append(l.toks, token{kind: tEOF, pos: l.pos})
			return l.toks, nil
		}
		if err := l.next(); err != nil {
			return nil, err
		}
	}
}

func (l *lexer) skipSpace() {
	for l.pos < len(l.src) {
		switch {
		case strings.HasPrefix(l.src[l.pos:], "//"):
			i := strings.IndexByte(l.src[l.pos:], '\n')
			if i < 0 {
				l.pos = len(l.src)
			} else {
				l.pos += i
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			i := strings.Index(l.src[l.pos+2:], "*/")
			if i < 0 {
				l.pos = len(l.src)
			} else {
				l.pos += i + 4
			}
		default:
			r, n := utf8.DecodeRuneInString(l.src[l.pos:])
			if !unicode.IsSpace(r) && r != '\uFEFF' {
				return
			}
			l.pos += n
		}
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (l *lexer) next() error {
	start, c := l.pos, l.src[l.pos]
	switch {
	case c == '\'' || c == '"' || c == '`':
		s, err := l.str(c)
		if err != nil {
			return err
		}
		l.toks = append(l.toks, token{kind: tString, text: s, pos: start})
	case isDigit(c) || (c == '-' && l.pos+1 < len(l.src) && (isDigit(l.src[l.pos+1]) || l.src[l.pos+1] == '.')):
		l.pos++
		for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || strings.IndexByte(".eE+-_", l.src[l.pos]) >= 0) {
			l.pos++
		}
		l.toks = append(l.toks, token{kind: tNumber, text: strings.ReplaceAll(l.src[start:l.pos], "_", ""), pos: start})
	case isIdentStart(c):
		for l.pos < len(l.src) && (isIdentStart(l.src[l.pos]) || isDigit(l.src[l.pos])) {
			l.pos++
		}
		l.toks = append(l.toks, token{kind: tIdent, text: l.src[start:l.pos], pos: start})
	case strings.IndexByte("{}[]():,;=+<>.?|&!*/", c) >= 0:
		l.pos++
		l.toks = append(l.toks, token{kind: tPunct, text: string(c), pos: start})
	default:
		return fmt.Errorf("unexpected character %q at offset %d", c, start)
	}
	return nil
}

// str decodes a quoted string with JavaScript escape rules. A template
// literal is accepted only when it has no `${` substitution.
func (l *lexer) str(quote byte) (string, error) {
	start := l.pos
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == quote:
			l.pos++
			return b.String(), nil
		case c == '\n' && quote != '`':
			return "", fmt.Errorf("unterminated string at offset %d", start)
		case quote == '`' && c == '$' && strings.HasPrefix(l.src[l.pos:], "${"):
			return "", fmt.Errorf("template substitution at offset %d", l.pos)
		case c == '\\':
			l.pos++
			if l.pos >= len(l.src) {
				return "", fmt.Errorf("unterminated string at offset %d", start)
			}
			if err := l.escape(&b); err != nil {
				return "", err
			}
		default:
			r, n := utf8.DecodeRuneInString(l.src[l.pos:])
			b.WriteRune(r)
			l.pos += n
		}
	}
	return "", fmt.Errorf("unterminated string at offset %d", start)
}

func (l *lexer) escape(b *strings.Builder) error {
	c := l.src[l.pos]
	l.pos++
	switch c {
	case 'n':
		b.WriteByte('\n')
	case 'r':
		b.WriteByte('\r')
	case 't':
		b.WriteByte('\t')
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'v':
		b.WriteByte('\v')
	case '0':
		b.WriteByte(0)
	case '\n':
		// line continuation
	case 'x', 'u':
		digits := 2
		if c == 'u' {
			digits = 4
		}
		var hex string
		if c == 'u' && l.pos < len(l.src) && l.src[l.pos] == '{' {
			end := strings.IndexByte(l.src[l.pos:], '}')
			if end < 0 {
				return fmt.Errorf("bad \\u escape at offset %d", l.pos)
			}
			hex = l.src[l.pos+1 : l.pos+end]
			l.pos += end + 1
		} else {
			if l.pos+digits > len(l.src) {
				return fmt.Errorf("bad \\%c escape at offset %d", c, l.pos)
			}
			hex = l.src[l.pos : l.pos+digits]
			l.pos += digits
		}
		n, err := strconv.ParseUint(hex, 16, 32)
		if err != nil || n > unicode.MaxRune {
			return fmt.Errorf("bad \\%c escape %q", c, hex)
		}
		b.WriteRune(rune(n)) //nolint:gosec // bounded by unicode.MaxRune above
	default:
		// \\ \' \" and every other escaped character stand for the character.
		r, size := utf8.DecodeRuneInString(l.src[l.pos-1:])
		b.WriteRune(r)
		l.pos += size - 1
	}
	return nil
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) take() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) isPunct(s string) bool {
	t := p.peek()
	return t.kind == tPunct && t.text == s
}

func (p *parser) expect(s string) error {
	if !p.isPunct(s) {
		return p.errorf("want %q", s)
	}
	p.i++
	return nil
}

func (p *parser) errorf(format string, a ...any) error {
	t := p.peek()
	got := t.text
	if t.kind == tEOF {
		got = "end of file"
	}
	return fmt.Errorf("offset %d near %q: %s", t.pos, got, fmt.Sprintf(format, a...))
}

// decl is one `export const NAME = value`.
type decl struct {
	Name  string
	Value any
}

// parseModule returns the exported constants of a module.
func parseModule(src string) ([]decl, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var out []decl
	for p.peek().kind != tEOF {
		t := p.peek()
		switch {
		case t.kind == tIdent && t.text == "export":
			p.i++
			if k := p.take(); k.text != "const" {
				return nil, p.errorf("only `export const` is supported")
			}
			name := p.take()
			if name.kind != tIdent {
				return nil, p.errorf("want a constant name")
			}
			for !p.isPunct("=") { // the type annotation
				if p.peek().kind == tEOF || p.isPunct(";") {
					return nil, p.errorf("constant %s has no value", name.text)
				}
				p.i++
			}
			p.i++
			v, err := p.value()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name.text, err)
			}
			out = append(out, decl{Name: name.text, Value: v})
			if p.isPunct(";") {
				p.i++
			}
		case t.kind == tIdent && t.text == "import":
			for p.peek().kind != tEOF && !p.isPunct(";") {
				p.i++
			}
			p.i++
		default:
			return nil, p.errorf("unsupported statement")
		}
	}
	return out, nil
}

func (p *parser) value() (any, error) {
	v, err := p.primary()
	if err != nil {
		return nil, err
	}
	if s, ok := v.(string); ok {
		for p.isPunct("+") {
			p.i++
			n, err := p.primary()
			if err != nil {
				return nil, err
			}
			ns, ok := n.(string)
			if !ok {
				return nil, p.errorf("only strings can be concatenated")
			}
			s += ns
		}
		v = s
	}
	if t := p.peek(); t.kind == tIdent && t.text == "as" { // `as const`
		p.i += 2
	}
	return v, nil
}

func (p *parser) primary() (any, error) {
	t := p.peek()
	switch {
	case t.kind == tString:
		p.i++
		return t.text, nil
	case t.kind == tNumber:
		p.i++
		n, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, p.errorf("bad number")
		}
		return n, nil
	case t.kind == tIdent && (t.text == "true" || t.text == "false"):
		p.i++
		return t.text == "true", nil
	case t.kind == tIdent && t.text == "null":
		p.i++
		return nil, nil
	case p.isPunct("["):
		return p.array()
	case p.isPunct("{"):
		return p.object()
	}
	return nil, p.errorf("only literal values are supported")
}

func (p *parser) array() ([]any, error) {
	p.i++
	out := []any{}
	for !p.isPunct("]") {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.isPunct(",") {
			p.i++
		} else if !p.isPunct("]") {
			return nil, p.errorf("want , or ]")
		}
	}
	p.i++
	return out, nil
}

func (p *parser) object() (map[string]any, error) {
	p.i++
	out := map[string]any{}
	for !p.isPunct("}") {
		k := p.take()
		if k.kind != tIdent && k.kind != tString && k.kind != tNumber {
			return nil, p.errorf("want a property name")
		}
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out[k.text] = v
		if p.isPunct(",") {
			p.i++
		} else if !p.isPunct("}") {
			return nil, p.errorf("want , or }")
		}
	}
	p.i++
	return out, nil
}
