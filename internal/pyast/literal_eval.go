package pyast

import "math/big"

// Container values LiteralEval returns; scalars are the Constant value types.
type (
	TupleValue []any
	SetValue   []any
	DictValue  struct{ Keys, Values []any }
)

// LiteralEval is ast.literal_eval over a parsed node: Constant, Tuple, List, Set, Dict,
// set(), unary +/- on numbers and real +/- imaginary. ok is false where Python raises
// ValueError.
// ponytail: Dict keeps every pair in source order instead of applying Python's key
// equality; no consumer dedupes keys.
func LiteralEval(n Node) (v any, ok bool) {
	switch x := n.(type) {
	case *Constant:
		return x.Value, true
	case *Tuple:
		return convertElts(x.Elts, func(e []any) any { return TupleValue(e) })
	case *List:
		return convertElts(x.Elts, func(e []any) any { return e })
	case *Set:
		return convertElts(x.Elts, func(e []any) any { return SetValue(e) })
	case *Call:
		if f, isName := x.Func.(*Name); isName && f.Id == "set" && len(x.Args) == 0 && len(x.Keywords) == 0 {
			return SetValue{}, true
		}
	case *Dict:
		d := DictValue{}
		for i := range x.Keys {
			if x.Keys[i] == nil {
				return nil, false
			}
			k, ok := LiteralEval(x.Keys[i])
			if !ok {
				return nil, false
			}
			val, ok := LiteralEval(x.Values[i])
			if !ok {
				return nil, false
			}
			d.Keys = append(d.Keys, k)
			d.Values = append(d.Values, val)
		}
		return d, true
	case *BinOp:
		_, add := x.Op.(*Add)
		_, sub := x.Op.(*Sub)
		if add || sub {
			left, ok := convertSignedNum(x.Left)
			if !ok {
				return nil, false
			}
			right, ok := convertNum(x.Right)
			if !ok {
				return nil, false
			}
			r, isComplex := right.(complex128)
			lf, isReal := toFloat(left)
			if isComplex && isReal {
				if add {
					return complex(lf, 0) + r, true
				}
				return complex(lf, 0) - r, true
			}
		}
	}
	return convertSignedNum(n)
}

func convertElts(elts []Expr, wrap func([]any) any) (any, bool) {
	out := make([]any, 0, len(elts))
	for _, e := range elts {
		v, ok := LiteralEval(e)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return wrap(out), true
}

func convertNum(n Node) (any, bool) {
	c, ok := n.(*Constant)
	if !ok {
		return nil, false
	}
	switch c.Value.(type) {
	case int64, *big.Int, float64, complex128:
		return c.Value, true
	}
	return nil, false
}

func convertSignedNum(n Node) (any, bool) {
	u, ok := n.(*UnaryOp)
	if !ok {
		return convertNum(n)
	}
	_, plus := u.Op.(*UAdd)
	_, minus := u.Op.(*USub)
	if !plus && !minus {
		return nil, false
	}
	v, ok := convertNum(u.Operand)
	if !ok || plus {
		return v, ok
	}
	switch x := v.(type) {
	case int64:
		return -x, true
	case *big.Int:
		return new(big.Int).Neg(x), true
	case float64:
		return -x, true
	case complex128:
		return -x, true
	}
	return nil, false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case *big.Int:
		f, _ := new(big.Float).SetInt(x).Float64()
		return f, true
	case float64:
		return x, true
	}
	return 0, false
}
