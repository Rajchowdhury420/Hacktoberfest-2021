#!/usr/bin/python3

import angr
import claripy

project = angr.Project('./GoldDigger')
inp = claripy.BVS("inp", 0x1c*8)
entry = project.factory.entry_state(args=['./GoldDigger',inp])
manager = project.factory.simgr(entry)
manager.explore(find=0x00401339,avoid=[0x00401347,0x0040130f])
if manager.found:
    print(manager.found[0].solver.eval(inp, cast_to=bytes))
else:
    print('Not Found!')
