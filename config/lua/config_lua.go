package config_lua

import (
	"time"

	lua "github.com/yuin/gopher-lua"
)

func UsualRunFunction(functionname string, filename string) error {

	L := lua.NewState()
	if err := L.DoFile(filename); err != nil {
		return err
	}

	fn := L.GetGlobal(functionname)

	if lf, ok := fn.(*lua.LFunction); ok {
		if err := L.CallByParam(lua.P{
			Fn:      lf,
			NRet:    0,
			Protect: true,
		}, lua.LString(time.Now().Format("2006-01-02 15:04:05"))); err != nil {
			return err
		}
	}

	return nil
}

func RunFunctionIntParam(functionname string, num int, filename string) error {

	L := lua.NewState()
	if err := L.DoFile(filename); err != nil {
		return err
	}

	fn := L.GetGlobal(functionname)

	if lf, ok := fn.(*lua.LFunction); ok {
		if err := L.CallByParam(lua.P{
			Fn:      lf,
			NRet:    0,
			Protect: true,
		}, lua.LString(time.Now().Format("2006-01-02 15:04:05")), lua.LNumber(num)); err != nil {
			return err
		}
	}

	return nil
}
