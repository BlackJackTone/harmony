import sys
import cxl

# check to see if this state is bad
def mutex(state):
    rcs = state.labels["rcs"]
    wcs = state.labels["wcs"]
    nrds = 0
    nwrs = 0
    for ctx in state.ctxbag.keys():
        if ctx.pc == rcs:
            nrds += 1
        elif ctx.pc == wcs:
            nwrs += 1
    return (nrds == 0 and nwrs <= 1) or nwrs == 0

def main():
    (code, labels) = cxl.compile(sys.stdin, "<stdin>")
    rcs = labels["rcs"]
    wcs = labels["wcs"]
    cxl.run(code, labels, mutex, [
        (("reader", 0), rcs), (("reader", 1), rcs),
        (("writer", 0), wcs), (("writer", 1), wcs)
    ])

if __name__ == "__main__":
    main()
