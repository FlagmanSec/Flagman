# flows: reading feature files

`read_flows(*paths)` reads one or more feature files written by
`flagmand extract` into one pandas table:

```python
from flagman_ml.flows import read_flows

flows = read_flows("fixtures/lab-ssh-logins.parquet")
flows.frame       # 24 rows: source, row, 7 metadata columns, 37 features
flows.inputs()    # the 37 features only: the model inputs
flows.schema      # the features, their kinds, units and shortcut notes
flows.files[0]    # name, rows, SHA-256, capture name, writer
```

- `source` (the file's name) and `row` (the position in it) name each flow
  for good; labels and predictions join back on them.
- Category features (`protocol`, `dst_port_class`, `tcp_outcome`) become
  pandas categories with **every** value of the schema, in its order, so the
  codes are the same in every file.
- Files read together must share the schema version, the feature list and
  the flow table settings (timeouts decide where flows are cut, so features
  made with other settings are not comparable). File names must differ.
- `schema.watched()` lists the features that may describe the lab instead
  of the attack (timing, sizes that follow the network): the shortcut audit
  starts from it.

| File | What it does |
|---|---|
| `schema.py` | the footer: schema version, features, metadata columns, flow table, capture |
| `read.py` | `read_flows`, `Flows`, `FlowFile` |
| `schema_test.py`, `read_test.py` | tests on the lab files, and on altered copies of them |
