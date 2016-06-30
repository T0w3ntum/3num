# 3num

### Required

The following libraries are required.

- python-libnmap
- tabulate

### Usage

At it's core, 3num will perform a fast port scan if only supplied with a host. 

```
3num.py -H 127.0.0.1
```

However, if you add -V to the scan it will then perform service verification scans on the discovered ports.

```
3num.py -H 127.0.0.1 -V
```

Take it a step further and run some intense scans. 3num will check the discovered services and run additional tools against them and save the output
to the provided destination.
(Currently only enum4linux supported)

```
3num.py -H 127.0.0.1 -i -o /tmp/
3num.py -H 127.0.0.1 -V -i -o /tmp/
```

If you want to save the port scan as tabular data in markdown format, you can supply it with the -t flag and -o. 

```
3num.py -H 127.0.0.1 -t -o /tmp/
```
