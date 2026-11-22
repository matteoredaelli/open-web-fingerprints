// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package whatweb

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file reads the small subset of Ruby that WhatWeb plugins use for their
// data: the `matches [ {...}, ... ]` list, and the string declarations
// (`name "X"`). Nothing is run. A construct outside the subset (string
// interpolation, concatenation, method calls on a value, %r, heredocs) is an
// error for the clause that holds it, never a guess.

// rubyRegexp is a /source/flags literal.
type rubyRegexp struct {
	Source string
	Flags  string
}

func (r rubyRegexp) String() string { return "/" + r.Source + "/" + r.Flags }

// softError is a lexical error after which the lexer has moved past the bad
// input: the clause that holds it is lost, the plugin is not.
type softError struct{ error }

func (e softError) Unwrap() error { return e.error }

type tokKind int

const (
	tkSym   tokKind = iota // :name
	tkStr                  // a string literal, already unescaped
	tkRegex                // a regular expression literal
	tkNum                  // an integer or float
	tkIdent                // true, false, nil or another bare word
	tkArrow                // =>
	tkPunct                // { } [ ] , ( ) + .
)

type token struct {
	kind tokKind
	text string
	re   rubyRegexp
	pos  int
}

// lexer reads tokens from src starting at pos. A `/` starts a regular
// expression only where a value can start (after =>, a comma or an opening
// bracket).
type lexer struct {
	src  string
	pos  int
	prev *token
}

func (l *lexer) regexAllowed() bool {
	if l.prev == nil {
		return true
	}
	switch l.prev.kind {
	case tkArrow:
		return true
	case tkPunct:
		return strings.Contains(",[({", l.prev.text)
	}
	return false
}

// next returns the next token, or ok=false at the end of the source.
func (l *lexer) next() (tok token, ok bool, err error) {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case ' ', '\t', '\n', '\r':
			l.pos++
		case '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		default:
			t, err := l.lex()
			if err != nil {
				return token{}, false, err
			}
			l.prev = &t
			return t, true, nil
		}
	}
	return token{}, false, nil
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (l *lexer) lex() (token, error) {
	start, c := l.pos, l.src[l.pos]
	switch {
	case c == '=' && strings.HasPrefix(l.src[l.pos:], "=>"):
		l.pos += 2
		return token{kind: tkArrow, text: "=>", pos: start}, nil
	case strings.IndexByte("{}[],()+.", c) >= 0:
		l.pos++
		return token{kind: tkPunct, text: string(c), pos: start}, nil
	case c == '\'' || c == '"':
		s, n, err := readString(l.src[l.pos:])
		if err != nil {
			if n > 0 {
				l.pos += n
				return token{}, softError{fmt.Errorf("%w at offset %d", err, start)}
			}
			return token{}, fmt.Errorf("%w at offset %d", err, start)
		}
		l.pos += n
		return token{kind: tkStr, text: s, pos: start}, nil
	case c == ':' && l.pos+1 < len(l.src) && isIdentByte(l.src[l.pos+1]):
		l.pos++
		b := l.pos
		for l.pos < len(l.src) && isIdentByte(l.src[l.pos]) {
			l.pos++
		}
		return token{kind: tkSym, text: l.src[b:l.pos], pos: start}, nil
	case c == '%' && l.pos+2 < len(l.src) && l.src[l.pos+1] == 'r' && strings.IndexByte("{([<!|", l.src[l.pos+2]) >= 0 && l.regexAllowed():
		re, n, err := readPercentRegexp(l.src[l.pos:])
		if err != nil {
			return token{}, fmt.Errorf("%w at offset %d", err, start)
		}
		l.pos += n
		return token{kind: tkRegex, re: re, pos: start}, nil
	case c == '/' && l.regexAllowed():
		re, n, err := readRegexp(l.src[l.pos:])
		if err != nil {
			return token{}, fmt.Errorf("%w at offset %d", err, start)
		}
		l.pos += n
		return token{kind: tkRegex, re: re, pos: start}, nil
	case c >= '0' && c <= '9' || c == '-' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9':
		l.pos++
		for l.pos < len(l.src) && (l.src[l.pos] >= '0' && l.src[l.pos] <= '9' || l.src[l.pos] == '.' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9') {
			l.pos++
		}
		return token{kind: tkNum, text: l.src[start:l.pos], pos: start}, nil
	case isIdentByte(c):
		for l.pos < len(l.src) && isIdentByte(l.src[l.pos]) {
			l.pos++
		}
		return token{kind: tkIdent, text: l.src[start:l.pos], pos: start}, nil
	}
	l.pos++
	return token{}, softError{fmt.Errorf("unexpected %q at offset %d", c, start)}
}

// readString reads a '...' or "..." literal at the start of s and returns its
// value and length. Interpolation (#{) is refused.
func readString(s string) (val string, n int, err error) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q:
			return b.String(), i + 1, nil
		case c == '#' && q == '"' && i+1 < len(s) && (s[i+1] == '{' || s[i+1] == '$' || s[i+1] == '@'):
			return "", literalEnd(s), fmt.Errorf("string interpolation")
		case c == '\\' && i+1 < len(s):
			i++
			e := s[i]
			if q == '\'' {
				if e == '\\' || e == '\'' {
					b.WriteByte(e)
				} else {
					b.WriteByte('\\')
					b.WriteByte(e)
				}
				continue
			}
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 's':
				b.WriteByte(' ')
			case '0':
				b.WriteByte(0)
			case 'x':
				j := i + 1
				for j < len(s) && j < i+3 && isHex(s[j]) {
					j++
				}
				if j == i+1 {
					return "", 0, fmt.Errorf("bad \\x escape")
				}
				v, _ := strconv.ParseUint(s[i+1:j], 16, 8)
				b.WriteByte(byte(v))
				i = j - 1
			case 'u':
				j := i + 1
				if j < len(s) && s[j] == '{' {
					return "", 0, fmt.Errorf("unsupported \\u{} escape")
				}
				for j < len(s) && j < i+5 && isHex(s[j]) {
					j++
				}
				if j != i+5 {
					return "", 0, fmt.Errorf("bad \\u escape")
				}
				v, _ := strconv.ParseUint(s[i+1:j], 16, 16) // four hex digits: at most 0xFFFF
				var buf [4]byte
				b.Write(buf[:utf8.EncodeRune(buf[:], rune(uint16(v)))])
				i = j - 1
			case '\n':
			default:
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

// literalEnd returns the length of the quoted literal at the start of s, or 0
// if it is not closed.
func literalEnd(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case s[0]:
			return i + 1
		}
	}
	return 0
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// readRegexp reads /source/flags at the start of s. Interpolation and the x
// flag (free spacing) are refused.
func readRegexp(s string) (re rubyRegexp, n int, err error) {
	inClass := false
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
		case c == '\n':
			return rubyRegexp{}, 0, fmt.Errorf("regular expression over several lines")
		case c == '#' && i+1 < len(s) && s[i+1] == '{':
			return rubyRegexp{}, 0, fmt.Errorf("regular expression interpolation")
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			j := i + 1
			for j < len(s) && strings.IndexByte("imxounse", s[j]) >= 0 {
				j++
			}
			re = rubyRegexp{Source: s[1:i], Flags: s[i+1 : j]}
			if strings.Contains(re.Flags, "x") {
				return rubyRegexp{}, 0, fmt.Errorf("regular expression with the x flag")
			}
			return re, j, nil
		}
	}
	return rubyRegexp{}, 0, fmt.Errorf("unterminated regular expression")
}

// readPercentRegexp reads %r{source}flags (also with (), [], <>, ! and |).
func readPercentRegexp(s string) (rubyRegexp, int, error) {
	open := s[2]
	closing := map[byte]byte{'{': '}', '(': ')', '[': ']', '<': '>', '!': '!', '|': '|'}[open]
	depth := 0
	for i := 3; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
		case c == '\n':
			return rubyRegexp{}, 0, fmt.Errorf("regular expression over several lines")
		case c == '#' && i+1 < len(s) && s[i+1] == '{':
			return rubyRegexp{}, 0, fmt.Errorf("regular expression interpolation")
		case c == closing && depth == 0:
			j := i + 1
			for j < len(s) && strings.IndexByte("imxounse", s[j]) >= 0 {
				j++
			}
			re := rubyRegexp{Source: s[3:i], Flags: s[i+1 : j]}
			if strings.Contains(re.Flags, "x") {
				return rubyRegexp{}, 0, fmt.Errorf("regular expression with the x flag")
			}
			return re, j, nil
		case c == closing:
			depth--
		case c == open && open != closing:
			depth++
		}
	}
	return rubyRegexp{}, 0, fmt.Errorf("unterminated regular expression")
}

// rubyValue is a parsed value: string, rubyRegexp, float64, bool, nil, []any or
// map[string]any.
type rubyValue = any

// parser parses a bracketed list of hashes from the token stream.
type parser struct {
	l    *lexer
	peek *token
}

func (p *parser) fetch() (token, bool, error) {
	if p.peek != nil {
		t := *p.peek
		p.peek = nil
		return t, true, nil
	}
	return p.l.next()
}

func (p *parser) look() (token, bool, error) {
	if p.peek != nil {
		return *p.peek, true, nil
	}
	t, ok, err := p.l.next()
	if err != nil || !ok {
		return t, ok, err
	}
	p.peek = &t
	return t, true, nil
}

func (p *parser) punct(s string) bool {
	t, ok, err := p.look()
	return err == nil && ok && t.kind == tkPunct && t.text == s
}

// parseMatches parses `[ {..}, {..} ]`, the lexer being just after the opening
// bracket. A hash that cannot be read is returned as nil in its place and its
// message in bad; the parse continues with the next hash. A lexical error
// stops everything and is returned as err.
func (p *parser) parseMatches() (hashes []map[string]rubyValue, bad []string, err error) {
	for {
		t, ok, err := p.look()
		var soft softError
		if errors.As(err, &soft) {
			bad = append(bad, soft.Error())
			continue
		}
		if err != nil {
			return hashes, bad, err
		}
		if !ok {
			return hashes, bad, fmt.Errorf("matches list not closed")
		}
		switch {
		case t.kind == tkPunct && t.text == "]":
			_, _, _ = p.fetch()
			return hashes, bad, nil
		case t.kind == tkPunct && t.text == ",":
			_, _, _ = p.fetch()
		case t.kind == tkPunct && t.text == "{":
			h, herr := p.hash()
			if herr != nil {
				var fatal fatalError
				if errors.As(herr, &fatal) {
					return hashes, bad, fatal.error
				}
				bad = append(bad, herr.Error())
				if err := p.resync(1); err != nil {
					return hashes, bad, err
				}
				continue
			}
			hashes = append(hashes, h)
		default:
			bad = append(bad, fmt.Sprintf("unexpected %q in the matches list", t.text))
			_, _, _ = p.fetch()
			if err := p.resync(0); err != nil {
				return hashes, bad, err
			}
		}
	}
}

// fatalError is a lexical error that ends the whole plugin.
type fatalError struct{ error }

// lexErr classifies an error from the lexer: soft errors lose one clause.
func lexErr(err error) error {
	var soft softError
	if errors.As(err, &soft) {
		return soft.error
	}
	return fatalError{err}
}

// resync drops tokens until the next top-level comma or the closing bracket of
// the list (not consumed), skipping nested brackets. depth is how many
// brackets are open: 1 inside a hash whose closing brace has not been read.
func (p *parser) resync(depth int) error {
	for {
		t, ok, err := p.look()
		var soft softError
		if errors.As(err, &soft) {
			continue
		}
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("matches list not closed")
		}
		if t.kind == tkPunct {
			switch t.text {
			case "{", "[", "(":
				depth++
			case "}", ")":
				depth--
			case "]":
				if depth <= 0 {
					return nil
				}
				depth--
			case ",":
				if depth <= 0 {
					return nil
				}
			}
		}
		_, _, _ = p.fetch()
	}
}

// hash parses { :key => value, ... }, the opening brace being next.
func (p *parser) hash() (map[string]rubyValue, error) {
	_, _, _ = p.fetch() // {
	out := map[string]rubyValue{}
	for {
		t, ok, err := p.fetch()
		if err != nil {
			return nil, lexErr(err)
		}
		if !ok {
			return nil, fmt.Errorf("hash not closed")
		}
		switch {
		case t.kind == tkPunct && t.text == "}":
			return out, nil
		case t.kind == tkPunct && t.text == ",":
			continue
		case t.kind == tkSym || t.kind == tkStr:
			arrow, ok, err := p.fetch()
			if err != nil {
				return nil, lexErr(err)
			}
			if !ok || arrow.kind != tkArrow {
				return nil, fmt.Errorf("key %q without =>", t.text)
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			out[t.text] = v
		default:
			return nil, fmt.Errorf("unexpected %q in a hash", t.text)
		}
	}
}

func (p *parser) value() (rubyValue, error) {
	t, ok, err := p.fetch()
	if err != nil {
		return nil, lexErr(err)
	}
	if !ok {
		return nil, fmt.Errorf("value missing")
	}
	var v rubyValue
	switch t.kind {
	case tkStr:
		v = t.text
	case tkRegex:
		v = t.re
	case tkNum:
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("number %q", t.text)
		}
		v = f
	case tkSym:
		v = t.text
	case tkIdent:
		switch t.text {
		case "true":
			v = true
		case "false":
			v = false
		case "nil":
			v = nil
		default:
			return nil, fmt.Errorf("unsupported expression %q", t.text)
		}
	case tkPunct:
		switch t.text {
		case "[":
			list := []rubyValue{}
			for {
				n, ok, err := p.look()
				if err != nil {
					return nil, lexErr(err)
				}
				if !ok {
					return nil, fmt.Errorf("array not closed")
				}
				if n.kind == tkPunct && n.text == "]" {
					_, _, _ = p.fetch()
					break
				}
				if n.kind == tkPunct && n.text == "," {
					_, _, _ = p.fetch()
					continue
				}
				e, err := p.value()
				if err != nil {
					return nil, err
				}
				list = append(list, e)
			}
			v = list
		default:
			return nil, fmt.Errorf("unsupported %q in a value", t.text)
		}
	default:
		return nil, fmt.Errorf("unsupported token %q in a value", t.text)
	}
	// A method call or an operator on the value is an expression, not data.
	if p.punct("+") || p.punct(".") || p.punct("(") {
		return nil, fmt.Errorf("value is an expression (operator or method call)")
	}
	return v, nil
}

var matchesStart = regexp.MustCompile(`(?m)^[ \t]*matches[ \t]*\[`)

// readMatches finds the plugin's `matches [...]` list and parses it. found is
// false when the plugin has none.
func readMatches(src string) (hashes []map[string]rubyValue, bad []string, found bool, err error) {
	loc := matchesStart.FindStringIndex(src)
	if loc == nil {
		return nil, nil, false, nil
	}
	p := &parser{l: &lexer{src: src, pos: loc[1]}}
	hashes, bad, err = p.parseMatches()
	return hashes, bad, true, err
}

// declaration reads `name "value"` at the start of a line: a string literal on
// one declaration line of the plugin (name, description, website, version).
func declaration(src, key string) (string, bool) {
	re := regexp.MustCompile(`(?m)^[ \t]*` + key + `[ \t]+['"]`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return "", false
	}
	start := loc[1] - 1
	s, _, err := readString(src[start:])
	if err != nil {
		return "", false
	}
	return s, true
}
