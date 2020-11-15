package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type rule struct{ namespace, filename string }
type rules []rule

func (r *rules) Set(arg string) error {
	if len(arg) == 0 {
		return errors.New("empty rule specification")
	}
	a := strings.SplitN(arg, ":", 2)
	switch len(a) {
	case 1:
		*r = append(*r, rule{filename: a[0]})
	case 2:
		*r = append(*r, rule{namespace: a[0], filename: a[1]})
	}
	return nil
}

func (r *rules) String() string {
	var s string
	for _, rule := range *r {
		if len(s) > 0 {
			s += " "
		}
		if rule.namespace != "" {
			s += rule.namespace + ":"
		}
		s += rule.filename
	}
	return s
}

type variables map[string]interface{}

func (v *variables) Set(s string) error {
	if *v == nil {
		*v = make(variables)
	}
	kv := strings.SplitN(s, "=", 2)
	if len(kv) != 2 {
		return errors.New("expected key=value")
	}
	if _, ok := (*v)[kv[0]]; ok {
		return fmt.Errorf("duplicate identifier '%s'", kv[0])
	}
	if kv[1] == "true" {
		(*v)[kv[0]] = true
	} else if kv[1] == "false" {
		(*v)[kv[0]] = false
	} else if i, err := strconv.Atoi(kv[1]); err == nil {
		(*v)[kv[0]] = i
	} else if f, err := strconv.ParseFloat(kv[1], 64); err == nil {
		(*v)[kv[0]] = f
	} else {
		(*v)[kv[0]] = kv[1]
	}
	return nil
}

func (v *variables) String() string {
	var s string
	for k, v := range *v {
		if s != "" {
			s += " "
		}
		s += fmt.Sprintf("%s=%s", k, v)
	}
	return s
}
