package flow

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Predicate 是 M0 阶段的过滤谓词。完整 DSL 将在 M1 扩展（括号、正则、header.*）。
type Predicate func(*Flow) bool

var comparisonRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]*)(>=|<=|!=|!~|=|>|<|~)(.+)$`)
var globEscapeRe = regexp.MustCompile(`[.+^${}()|\[\]\\]`)

func alwaysTrue(*Flow) bool { return true }

// CompileFilter 支持 and/or/not、字段冒号写法与比较运算符，例如：
//
//	method:POST and status:>=400 and host:*.example.com
//	(status 由字段名与运算符组成，M0 不支持括号)
func CompileFilter(expr string) (Predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return alwaysTrue, nil
	}
	if strings.ContainsAny(expr, "()") {
		return nil, fmt.Errorf("过滤语法暂不支持括号")
	}

	orParts, err := splitLogical(expr, "or")
	if err != nil {
		return nil, err
	}

	var groups []Predicate
	for _, orPart := range orParts {
		andParts, err := splitLogical(orPart, "and")
		if err != nil {
			return nil, err
		}
		var terms []Predicate
		for _, raw := range andParts {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			negate := false
			if strings.HasPrefix(strings.ToLower(raw), "not ") {
				negate = true
				raw = strings.TrimSpace(raw[4:])
			}
			p, err := compileTerm(raw)
			if err != nil {
				return nil, err
			}
			if negate {
				inner := p
				p = func(f *Flow) bool { return !inner(f) }
			}
			terms = append(terms, p)
		}
		if len(terms) == 0 {
			continue
		}
		group := terms
		groups = append(groups, func(f *Flow) bool {
			for _, p := range group {
				if !p(f) {
					return false
				}
			}
			return true
		})
	}

	if len(groups) == 0 {
		return alwaysTrue, nil
	}
	return func(f *Flow) bool {
		for _, p := range groups {
			if p(f) {
				return true
			}
		}
		return false
	}, nil
}

func compileTerm(term string) (Predicate, error) {
	if m := comparisonRe.FindStringSubmatch(term); m != nil {
		return compileField(m[1], m[2], unquote(strings.TrimSpace(m[3])))
	}
	if idx := strings.Index(term, ":"); idx > 0 {
		field := term[:idx]
		rest := strings.TrimSpace(term[idx+1:])
		op := "="
		for _, candidate := range []string{">=", "<=", "!=", "!~", ">", "<", "=", "~"} {
			if strings.HasPrefix(rest, candidate) {
				op = candidate
				rest = strings.TrimSpace(rest[len(candidate):])
				break
			}
		}
		value := unquote(rest)
		if value == "" {
			return nil, fmt.Errorf("过滤条件 %q 缺少值", term)
		}
		return compileField(field, op, value)
	}
	return compilePlain(term), nil
}

func compilePlain(term string) Predicate {
	needle := strings.ToLower(unquote(term))
	return func(f *Flow) bool {
		return strings.Contains(strings.ToLower(f.Host), needle) ||
			strings.Contains(strings.ToLower(f.Path), needle) ||
			strings.Contains(strings.ToLower(f.Method), needle) ||
			strings.Contains(strings.ToLower(bodyText(f)), needle)
	}
}

func compileField(field, op, value string) (Predicate, error) {
	field = strings.ToLower(field)
	op = normalizeOp(op)

	switch field {
	case "method":
		values := splitList(value)
		return func(f *Flow) bool {
			for _, v := range values {
				if strings.EqualFold(f.Method, v) {
					return op != "!=" && op != "!~"
				}
			}
			return op == "!=" || op == "!~"
		}, nil

	case "host", "path", "url", "mime":
		glob, err := makeGlobPredicate(value)
		if err != nil {
			return nil, err
		}
		return func(f *Flow) bool {
			var actual string
			switch field {
			case "host":
				actual = f.Host
			case "path":
				actual = f.Path
			case "url":
				actual = f.URL()
			case "mime":
				actual = f.Mime
			}
			matched := glob(actual)
			if op == "!=" || op == "!~" {
				return !matched
			}
			return matched
		}, nil

	case "scheme", "mode", "state", "app", "process", "origin", "ip":
		needle := strings.ToLower(value)
		return func(f *Flow) bool {
			var actual string
			switch field {
			case "scheme":
				actual = f.Scheme
			case "mode":
				actual = string(f.Mode)
			case "state":
				actual = string(f.State)
			case "app", "process":
				actual = f.Client.App
			case "origin":
				actual = f.Client.Origin
			case "ip":
				actual = f.Client.IP + " " + f.Server.IP
			}
			matched := strings.Contains(strings.ToLower(actual), needle)
			if op == "!=" || op == "!~" {
				return !matched
			}
			return matched
		}, nil

	case "status":
		if n, ok := parseStatusRange(value); ok {
			return func(f *Flow) bool {
				matched := f.StatusCode/100 == n
				if op == "!=" || op == "!~" {
					return !matched
				}
				return matched
			}, nil
		}
		target, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("status 值无效: %q", value)
		}
		return func(f *Flow) bool {
			return compareInt(f.StatusCode, target, op)
		}, nil

	case "size", "reqsize", "respsize":
		target, err := parseBytes(value)
		if err != nil {
			return nil, err
		}
		return func(f *Flow) bool {
			var actual int64
			switch field {
			case "size":
				actual = f.ReqSize + f.RespSize
			case "reqsize":
				actual = f.ReqSize
			case "respsize":
				actual = f.RespSize
			}
			return compareInt64(actual, target, op)
		}, nil

	case "duration":
		target, err := parseMillis(value)
		if err != nil {
			return nil, err
		}
		return func(f *Flow) bool {
			return compareInt64(f.DurationMs, target, op)
		}, nil

	case "body":
		needle := strings.ToLower(value)
		return func(f *Flow) bool {
			matched := strings.Contains(strings.ToLower(bodyText(f)), needle)
			if op == "!=" || op == "!~" {
				return !matched
			}
			return matched
		}, nil

	case "tag":
		needle := strings.ToLower(value)
		return func(f *Flow) bool {
			matched := false
			for _, tag := range f.Tags {
				if strings.EqualFold(tag, needle) {
					matched = true
					break
				}
			}
			if op == "!=" || op == "!~" {
				return !matched
			}
			return matched
		}, nil

	case "port":
		target, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("port 值无效: %q", value)
		}
		return func(f *Flow) bool {
			return f.Client.Port == target || f.Server.Port == target || f.Port == target
		}, nil

	default:
		return nil, fmt.Errorf("未知过滤字段: %s", field)
	}
}

func normalizeOp(op string) string {
	switch op {
	case "!~":
		return "!="
	default:
		return op
	}
}

func makeGlobPredicate(pattern string) (func(string) bool, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return func(string) bool { return true }, nil
	}
	if !strings.ContainsAny(pattern, "*?") {
		return func(s string) bool {
			return strings.Contains(strings.ToLower(s), pattern)
		}, nil
	}

	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			ch := string(r)
			if globEscapeRe.MatchString(ch) {
				b.WriteString("\\")
			}
			b.WriteString(ch)
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("通配符 %q 无效: %w", pattern, err)
	}
	return func(s string) bool {
		return re.MatchString(strings.ToLower(s))
	}, nil
}

func splitLogical(expr, keyword string) ([]string, error) {
	var parts []string
	var b strings.Builder
	inQuote := false
	quote := rune(0)

	runes := []rune(expr)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inQuote {
			b.WriteRune(r)
			if r == quote {
				inQuote = false
			}
			continue
		}
		if r == '"' || r == '\'' {
			inQuote = true
			quote = r
			b.WriteRune(r)
			continue
		}
		if hasKeywordAt(runes, i, keyword) {
			parts = append(parts, b.String())
			b.Reset()
			i += len([]rune(keyword))
			continue
		}
		b.WriteRune(r)
	}
	if inQuote {
		return nil, fmt.Errorf("过滤表达式引号未闭合")
	}
	parts = append(parts, b.String())
	return parts, nil
}

func hasKeywordAt(runes []rune, i int, keyword string) bool {
	kw := []rune(keyword)
	if i+len(kw) > len(runes) {
		return false
	}
	for j, r := range kw {
		if runes[i+j] != r {
			return false
		}
	}
	prevOK := i == 0 || runes[i-1] == ' '
	next := i + len(kw)
	nextOK := next == len(runes) || runes[next] == ' '
	return prevOK && nextOK
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseStatusRange(value string) (int, bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	if len(v) == 3 && strings.HasSuffix(v, "xx") {
		n, err := strconv.Atoi(v[:1])
		if err == nil && n >= 1 && n <= 5 {
			return n, true
		}
	}
	return 0, false
}

func parseBytes(value string) (int64, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	multiplier := float64(1)
	switch {
	case strings.HasSuffix(v, "kb"):
		multiplier = 1024
		v = strings.TrimSuffix(v, "kb")
	case strings.HasSuffix(v, "mb"):
		multiplier = 1024 * 1024
		v = strings.TrimSuffix(v, "mb")
	case strings.HasSuffix(v, "gb"):
		multiplier = 1024 * 1024 * 1024
		v = strings.TrimSuffix(v, "gb")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, fmt.Errorf("大小值无效: %q", value)
	}
	return int64(n * multiplier), nil
}

func parseMillis(value string) (int64, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	multiplier := float64(1)
	switch {
	case strings.HasSuffix(v, "ms"):
		v = strings.TrimSuffix(v, "ms")
	case strings.HasSuffix(v, "s"):
		multiplier = 1000
		v = strings.TrimSuffix(v, "s")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, fmt.Errorf("耗时值无效: %q", value)
	}
	return int64(n * multiplier), nil
}

func compareInt(actual, target int, op string) bool {
	return compareInt64(int64(actual), int64(target), op)
}

func compareInt64(actual, target int64, op string) bool {
	switch op {
	case ">":
		return actual > target
	case ">=":
		return actual >= target
	case "<":
		return actual < target
	case "<=":
		return actual <= target
	case "!=", "!~":
		return actual != target
	default:
		return actual == target
	}
}

func bodyText(f *Flow) string {
	var b strings.Builder
	if f.Request != nil && f.Request.Body != nil {
		b.WriteString(f.Request.Body.Preview)
	}
	if f.Response != nil && f.Response.Body != nil {
		b.WriteString(f.Response.Body.Preview)
	}
	return b.String()
}
