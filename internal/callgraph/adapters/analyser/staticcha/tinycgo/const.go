package tinycgo

import (
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"strings"
)

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, cgo/const.go (the C constant-expression parser)

// This file implements a parser of a subset of the C language, just enough to
// parse common #define statements to Go constant expressions.

var (
	prefixParseFns map[token.Token]func(*tokenizer) (ast.Expr, *scanner.Error)
	precedences    = map[token.Token]int{
		token.OR:  precedenceOr,
		token.XOR: precedenceXor,
		token.AND: precedenceAnd,
		token.SHL: precedenceShift,
		token.SHR: precedenceShift,
		token.ADD: precedenceAdd,
		token.SUB: precedenceAdd,
		token.MUL: precedenceMul,
		token.QUO: precedenceMul,
		token.REM: precedenceMul,
	}
)

// See: https://en.cppreference.com/w/c/language/operator_precedence
const (
	precedenceLowest = iota + 1
	precedenceOr
	precedenceXor
	precedenceAnd
	precedenceShift
	precedenceAdd
	precedenceMul
	precedencePrefix
)

func init() {
	// This must be done in an init function to avoid an initialization order
	// failure.
	prefixParseFns = map[token.Token]func(*tokenizer) (ast.Expr, *scanner.Error){
		token.IDENT:  parseIdent,
		token.INT:    parseBasicLit,
		token.FLOAT:  parseBasicLit,
		token.STRING: parseBasicLit,
		token.CHAR:   parseBasicLit,
		token.LPAREN: parseParenExpr,
		token.SUB:    parseUnaryExpr,
	}
}

// parseConst parses the given string as a C constant.
func parseConst(pos token.Pos, fset *token.FileSet, value string, params []ast.Expr, callerPos token.Pos, f *cgoFile) (ast.Expr, *scanner.Error) {
	t := newTokenizer(pos, fset, value, f)

	// If params is non-nil (could be a zero length slice), this const is
	// actually a function-call like expression from another macro.
	// This means we have to parse a string like "(a, b) (a+b)".
	// We do this by parsing the parameters at the start and then treating the
	// following like a normal constant expression.
	if params != nil {
		if err := parseMacroParams(t, params, callerPos); err != nil {
			return nil, err
		}
	}

	expr, err := parseConstExpr(t, precedenceLowest)
	t.Next()
	if t.curToken != token.EOF {
		return nil, &scanner.Error{
			Pos: t.fset.Position(t.curPos),
			Msg: "unexpected token " + t.curToken.String() + ", expected end of expression",
		}
	}
	return expr, err
}

// parseMacroParams reads a function-like macro's "(a, b)" and binds each name
// to the argument the caller passed.
func parseMacroParams(t *tokenizer, params []ast.Expr, callerPos token.Pos) *scanner.Error {
	if t.curToken != token.LPAREN {
		return unexpectedToken(t, token.LPAREN)
	}
	t.Next()
	var paramIdents []string
	if t.curToken == token.RPAREN {
		t.Next()
	} else {
		for {
			if t.curToken != token.IDENT {
				return unexpectedToken(t, token.IDENT)
			}
			paramIdents = append(paramIdents, t.curValue)
			t.Next()
			if t.curToken == token.RPAREN {
				t.Next()
				break
			}
			if t.curToken != token.COMMA {
				return &scanner.Error{
					Pos: t.fset.Position(t.curPos),
					Msg: "unexpected token " + t.curToken.String() + " inside macro parameters, expected ',' or ')'",
				}
			}
			t.Next()
		}
	}
	if len(params) != len(paramIdents) {
		return &scanner.Error{
			Pos: t.fset.Position(callerPos),
			Msg: fmt.Sprintf("unexpected number of parameters: expected %d, got %d", len(paramIdents), len(params)),
		}
	}
	for i, p := range params {
		t.params[paramIdents[i]] = p
	}
	return nil
}

// parseConstExpr parses a stream of C tokens to a Go expression.
func parseConstExpr(t *tokenizer, precedence int) (ast.Expr, *scanner.Error) {
	if t.curToken == token.EOF {
		return nil, &scanner.Error{
			Pos: t.fset.Position(t.curPos),
			Msg: "empty constant",
		}
	}
	prefix := prefixParseFns[t.curToken]
	if prefix == nil {
		return nil, &scanner.Error{
			Pos: t.fset.Position(t.curPos),
			Msg: fmt.Sprintf("unexpected token %s", t.curToken),
		}
	}
	leftExpr, err := prefix(t)

	for t.peekToken != token.EOF && precedence < precedences[t.peekToken] {
		switch t.peekToken {
		case token.OR, token.XOR, token.AND, token.SHL, token.SHR, token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
			t.Next()
			leftExpr, err = parseBinaryExpr(t, leftExpr)
		}
	}

	return leftExpr, err
}

func parseIdent(t *tokenizer) (ast.Expr, *scanner.Error) {
	// If the identifier is one of the parameters of this function-like macro,
	// use the parameter value.
	if val, ok := t.params[t.curValue]; ok {
		return val, nil
	}

	if t.f != nil {
		// Check whether this identifier is actually a macro "call" with
		// parameters. In that case, we should parse the parameters and pass it
		// on to a new invocation of parseConst.
		if c, ok := t.f.names[t.curValue]; ok && t.peekToken == token.LPAREN && c.isFunctionLikeMacro() {
			return parseMacroCall(t, c)
		}

		// Normally the name is something defined in the file (like another
		// macro) which we get the declaration from using getASTDeclName.
		// This ensures that names that are only referenced inside a macro are
		// still getting defined.
		if c, ok := t.f.names[t.curValue]; ok {
			return &ast.Ident{
				NamePos: t.curPos,
				Name:    t.f.getASTDeclName(t.curValue, c, false),
			}, nil
		}
	}

	// t.f is nil during testing. This is a fallback.
	return &ast.Ident{
		NamePos: t.curPos,
		Name:    "C." + t.curValue,
	}, nil
}

// parseMacroCall expands a function-like macro "call": its arguments are
// parsed up to ')' and the macro's value is parsed with them bound.
func parseMacroCall(t *tokenizer, c cursor) (ast.Expr, *scanner.Error) {
	t.Next()
	t.Next()
	params := []ast.Expr{}
	if t.curToken != token.RPAREN {
		for {
			x, err := parseConstExpr(t, precedenceLowest)
			if err != nil {
				return nil, err
			}
			params = append(params, x)
			t.Next()
			if t.curToken == token.RPAREN {
				break
			}
			if t.curToken != token.COMMA {
				return nil, &scanner.Error{
					Pos: t.fset.Position(t.curPos),
					Msg: "unexpected token " + t.curToken.String() + ", ',' or ')'",
				}
			}
			t.Next()
		}
	}
	return parseConst(token.NoPos, t.fset, c.macro.value, params, t.curPos, t.f)
}

func parseBasicLit(t *tokenizer) (ast.Expr, *scanner.Error) {
	return &ast.BasicLit{
		ValuePos: t.curPos,
		Kind:     t.curToken,
		Value:    t.curValue,
	}, nil
}

func parseParenExpr(t *tokenizer) (ast.Expr, *scanner.Error) {
	lparen := t.curPos
	t.Next()
	x, err := parseConstExpr(t, precedenceLowest)
	if err != nil {
		return nil, err
	}
	t.Next()
	if t.curToken != token.RPAREN {
		return nil, unexpectedToken(t, token.RPAREN)
	}
	expr := &ast.ParenExpr{
		Lparen: lparen,
		X:      x,
		Rparen: t.curPos,
	}
	return expr, nil
}

func parseBinaryExpr(t *tokenizer, left ast.Expr) (ast.Expr, *scanner.Error) {
	expression := &ast.BinaryExpr{
		X:     left,
		Op:    t.curToken,
		OpPos: t.curPos,
	}
	precedence := precedences[t.curToken]
	t.Next()
	right, err := parseConstExpr(t, precedence)
	expression.Y = right
	return expression, err
}

func parseUnaryExpr(t *tokenizer) (ast.Expr, *scanner.Error) {
	expression := &ast.UnaryExpr{
		OpPos: t.curPos,
		Op:    t.curToken,
	}
	t.Next()
	x, err := parseConstExpr(t, precedencePrefix)
	expression.X = x
	return expression, err
}

// unexpectedToken returns an error of the form "unexpected token FOO, expected
// BAR".
func unexpectedToken(t *tokenizer, expected token.Token) *scanner.Error {
	return &scanner.Error{
		Pos: t.fset.Position(t.curPos),
		Msg: fmt.Sprintf("unexpected token %s, expected %s", t.curToken, expected),
	}
}

// tokenizer reads C source code and converts it to Go tokens.
type tokenizer struct {
	f                   *cgoFile
	curPos, peekPos     token.Pos
	fset                *token.FileSet
	curToken, peekToken token.Token
	curValue, peekValue string
	buf                 string
	params              map[string]ast.Expr
}

// newTokenizer initializes a new tokenizer, positioned at the first token in
// the string.
func newTokenizer(start token.Pos, fset *token.FileSet, buf string, f *cgoFile) *tokenizer {
	t := &tokenizer{
		f:         f,
		peekPos:   start,
		fset:      fset,
		buf:       buf,
		peekToken: token.ILLEGAL,
		params:    make(map[string]ast.Expr),
	}
	// Parse the first two tokens (cur and peek).
	t.Next()
	t.Next()
	return t
}

// Next consumes the next token in the stream. There is no return value, read
// the next token from the pos, token and value properties.
func (t *tokenizer) Next() {
	// The previous peek is now the current token.
	t.curPos = t.peekPos
	t.curToken = t.peekToken
	t.curValue = t.peekValue

	// Parse the next peek token.
	if t.peekPos != token.NoPos {
		t.peekPos += token.Pos(len(t.curValue))
	}
	for {
		if len(t.buf) == 0 {
			t.peekToken = token.EOF
			return
		}
		c := t.buf[0]
		switch {
		case isCSpace(c):
			// Skip whitespace.
			if t.peekPos != token.NoPos {
				t.peekPos++
			}
			t.buf = t.buf[1:]
			continue
		case len(t.buf) >= 2 && twoCharTokens[t.buf[:2]] != token.ILLEGAL:
			t.take(twoCharTokens[t.buf[:2]], 2)
		case oneCharTokens[c] != token.ILLEGAL:
			// TODO: ++ (increment) and -- (decrement) operators.
			t.take(oneCharTokens[c], 1)
		case c >= '0' && c <= '9':
			t.lexNumber()
		case isIdentStart(c):
			t.lexIdent()
		case c == '"':
			t.lexQuoted(token.STRING, '"')
		case c == '\'':
			t.lexQuoted(token.CHAR, '\'')
		default:
			t.peekToken = token.ILLEGAL
		}
		return
	}
}

func isCSpace(c byte) bool {
	return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v'
}

func isIdentStart(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' }

var twoCharTokens = map[string]token.Token{"||": token.LOR, "&&": token.LAND, "<<": token.SHL, ">>": token.SHR}

var oneCharTokens = map[byte]token.Token{
	'(': token.LPAREN, ')': token.RPAREN, ',': token.COMMA, '+': token.ADD, '-': token.SUB, '*': token.MUL,
	'/': token.QUO, '%': token.REM, '&': token.AND, '|': token.OR, '^': token.XOR,
}

// take makes the next n bytes the peek token tok.
func (t *tokenizer) take(tok token.Token, n int) {
	t.peekToken = tok
	t.peekValue = t.buf[:n]
	t.buf = t.buf[n:]
}

// lexNumber reads an integer or float constant, dropping C's suffixes.
func (t *tokenizer) lexNumber() {
	tokenLen := len(t.buf)
	hasDot := false
	for i, c := range t.buf {
		if c == '.' {
			hasDot = true
		}
		if c >= '0' && c <= '9' || c == '.' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			tokenLen = i + 1
		} else {
			break
		}
	}
	t.peekValue = t.buf[:tokenLen]
	t.buf = t.buf[tokenLen:]
	if hasDot {
		// Integer constants are more complicated than this but this is
		// a close approximation.
		t.peekToken = token.FLOAT
		t.peekValue = strings.TrimRight(t.peekValue, "f")
	} else {
		t.peekToken = token.INT
		t.peekValue = strings.TrimRight(t.peekValue, "uUlL")
	}
}

// lexIdent reads an identifier.
func (t *tokenizer) lexIdent() {
	tokenLen := len(t.buf)
	for i, c := range t.buf {
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' {
			tokenLen = i + 1
		} else {
			break
		}
	}
	t.take(token.IDENT, tokenLen)
}

// lexQuoted reads a string or char constant up to the first unescaped quote.
func (t *tokenizer) lexQuoted(tok token.Token, quote rune) {
	escape := false
	tokenLen := len(t.buf)
	for i, c := range t.buf {
		if i != 0 && c == quote && !escape {
			tokenLen = i + 1
			break
		}
		if !escape {
			escape = c == '\\'
		}
	}
	t.take(tok, tokenLen)
}

// SPDX-SnippetEnd
