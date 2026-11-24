// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package wafw00f

import (
	"fmt"
	"strconv"
	"strings"
)

// This file reads the small subset of Python that the plugins use. Nothing is
// executed: a plugin is a list of functions whose body is a sequence of
// `if <condition>: return True|False`, and a condition is a boolean
// combination of calls such as self.matchHeader(('Server', 'x')).

type tokKind int

const (
	tEOF tokKind = iota
	tString
	tNumber
	tName
	tSym
)

type token struct {
	kind tokKind
	text string
}

// logical is a statement joined from its physical lines.
type logical struct {
	indent int
	text   string
}

// logicalLines joins continuation lines (open brackets, a trailing backslash),
// drops comments and blank lines. Strings spanning lines are not supported;
// a statement that has one is returned as is and later fails to parse.
func logicalLines(src string) []logical {
	var out []logical
	var cur strings.Builder
	indent, depth := 0, 0
	open := false
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
		if !open {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			indent = len(line) - len(strings.TrimLeft(line, " \t"))
			cur.Reset()
			depth = 0
		}
		var quote byte
		cont := false
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case quote != 0:
				if c == '\\' && i+1 < len(line) {
					cur.WriteByte(c)
					i++
					c = line[i]
				} else if c == quote {
					quote = 0
				}
			case c == '\'' || c == '"':
				quote = c
			case c == '#':
				i = len(line)
				continue
			case c == '(' || c == '[' || c == '{':
				depth++
			case c == ')' || c == ']' || c == '}':
				depth--
			case c == '\\' && i == len(line)-1:
				cont = true
				continue
			}
			cur.WriteByte(c)
		}
		cur.WriteByte(' ')
		open = cont || depth > 0
		if !open {
			out = append(out, logical{indent: indent, text: strings.TrimSpace(cur.String())})
		}
	}
	if open {
		out = append(out, logical{indent: indent, text: strings.TrimSpace(cur.String())})
	}
	return out
}

func tokenize(s string) ([]token, error) {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '\'' || c == '"' || ((c == 'r' || c == 'R' || c == 'u' || c == 'b') && i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"')):
			raw := false
			if c != '\'' && c != '"' {
				raw = c == 'r' || c == 'R'
				if c == 'b' {
					return nil, fmt.Errorf("bytes literal")
				}
				i++
			}
			q := s[i]
			if strings.HasPrefix(s[i:], strings.Repeat(string(q), 3)) {
				return nil, fmt.Errorf("triple-quoted string")
			}
			j := i + 1
			var b strings.Builder
			closed := false
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					n := s[j+1]
					if raw {
						b.WriteByte('\\')
						b.WriteByte(n)
					} else {
						switch n {
						case '\\', '\'', '"':
							b.WriteByte(n)
						case 'n':
							b.WriteByte('\n')
						case 't':
							b.WriteByte('\t')
						default: // Python keeps an unknown escape as written
							b.WriteByte('\\')
							b.WriteByte(n)
						}
					}
					j += 2
					continue
				}
				if s[j] == q {
					closed = true
					j++
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string")
			}
			toks = append(toks, token{tString, b.String()})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			toks = append(toks, token{tNumber, s[i:j]})
			i = j
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			j := i
			for j < len(s) && (s[j] == '_' || (s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j < len(s) && (s[j] == '\'' || s[j] == '"') { // f"..." and other prefixes
				return nil, fmt.Errorf("string prefix %q", s[i:j])
			}
			toks = append(toks, token{tName, s[i:j]})
			i = j
		case strings.ContainsRune("().,=:", rune(c)):
			toks = append(toks, token{tSym, string(c)})
			i++
		default:
			return nil, fmt.Errorf("unexpected %q", string(c))
		}
	}
	return append(toks, token{kind: tEOF}), nil
}

// node is a parsed condition.
type node struct {
	op   string // "or", "and", "not", "call"
	kids []*node
	call *call
}

// call is self.method(...) or helper(self).
type call struct {
	method string // matchHeader, matchCookie, ... or "" for a helper
	helper string
	args   []arg
	attack *bool // the attack= keyword, nil when absent
}

// arg is a positional argument: a string, a number or a tuple of strings.
type arg struct {
	strs []string
	num  string
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) sym(s string) bool {
	if t := p.peek(); t.kind == tSym && t.text == s {
		p.pos++
		return true
	}
	return false
}
func (p *parser) kw(s string) bool {
	if t := p.peek(); t.kind == tName && t.text == s {
		p.pos++
		return true
	}
	return false
}

func parseCondition(s string) (*node, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, fmt.Errorf("trailing %q", p.peek().text)
	}
	return n, nil
}

func (p *parser) or() (*node, error) {
	n, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.kw("or") {
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		n = &node{op: "or", kids: []*node{n, r}}
	}
	return n, nil
}

func (p *parser) and() (*node, error) {
	n, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.kw("and") {
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		n = &node{op: "and", kids: []*node{n, r}}
	}
	return n, nil
}

func (p *parser) not() (*node, error) {
	if p.kw("not") {
		k, err := p.not()
		if err != nil {
			return nil, err
		}
		return &node{op: "not", kids: []*node{k}}, nil
	}
	if p.sym("(") {
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.sym(")") {
			return nil, fmt.Errorf("missing )")
		}
		return n, nil
	}
	return p.call()
}

func (p *parser) call() (*node, error) {
	t := p.next()
	if t.kind != tName {
		return nil, fmt.Errorf("expected a call, got %q", t.text)
	}
	c := &call{}
	if t.text == "self" {
		if !p.sym(".") {
			return nil, fmt.Errorf("expected . after self")
		}
		m := p.next()
		if m.kind != tName {
			return nil, fmt.Errorf("expected a method name")
		}
		c.method = m.text
	} else {
		c.helper = t.text
	}
	if !p.sym("(") {
		return nil, fmt.Errorf("expected (")
	}
	for !p.sym(")") {
		if len(c.args) > 0 || c.attack != nil {
			if !p.sym(",") {
				return nil, fmt.Errorf("expected ,")
			}
			if p.sym(")") {
				break
			}
		}
		if n := p.peek(); n.kind == tName && p.toks[p.pos+1].kind == tSym && p.toks[p.pos+1].text == "=" {
			p.pos += 2
			v := p.next()
			if n.text != "attack" || v.kind != tName || (v.text != "True" && v.text != "False") {
				return nil, fmt.Errorf("keyword %s", n.text)
			}
			b := v.text == "True"
			c.attack = &b
			continue
		}
		a, err := p.arg()
		if err != nil {
			return nil, err
		}
		c.args = append(c.args, a)
	}
	return &node{op: "call", call: c}, nil
}

func (p *parser) arg() (arg, error) {
	switch t := p.peek(); {
	case t.kind == tString:
		p.pos++
		return arg{strs: []string{t.text}}, nil
	case t.kind == tNumber:
		p.pos++
		if _, err := strconv.Atoi(t.text); err != nil {
			return arg{}, err
		}
		return arg{num: t.text}, nil
	case t.kind == tName && t.text == "self":
		p.pos++
		return arg{}, nil
	case t.kind == tSym && t.text == "(":
		p.pos++
		var strs []string
		for !p.sym(")") {
			if len(strs) > 0 && !p.sym(",") {
				return arg{}, fmt.Errorf("expected , in a tuple")
			}
			if p.sym(")") {
				break
			}
			s := p.next()
			if s.kind != tString {
				return arg{}, fmt.Errorf("a tuple of non-strings")
			}
			strs = append(strs, s.text)
		}
		return arg{strs: strs}, nil
	}
	return arg{}, fmt.Errorf("unsupported argument %q", p.peek().text)
}
