package yara

/*
#include <yara.h>
*/
import "C"

type Object struct{ cptr *C.YR_OBJECT }
