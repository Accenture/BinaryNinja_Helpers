# Const Finder

Script to find constants based on the context of their occurrence.

## Usage

Run the script and select name for the Index.
The search is based on the dictionary with constants which looks like this:
```
{
    "NAME OF THE CONSTANT SET": {
        0xff: {
            "type_of_use": ARRAY_INDEX,
            "direct_use_only": False
        },
        0xfe: {
            "type_of_use": ASSIGNMENTS,
            "direct_use_only": True
        },
    },
    "NAME OF OTHER CONSTANT SET": {
        0x01: {
            "type_of_use": CALLS,
            "direct_use_only": False
        }
    }
}
```

Notes:
* Constants (`0xff`, `0xfe` and `0x01` in the above example) must be specified as integers, not strings.
* The `type_of_use` could be a list of any custom `HighLevelILOperation` or one of the predefined groups:
    * `ASSIGNMENTS` - Any assignment.
    * `CALLS` - Parameter of a function call.
    * `INT_COMPARE` - Integer comparison (for example `<=`).
    * `FLOAT_COMPARE` - Float comparison.
    * `MATH` - Integer mathematical operation (for example `+`, `-`, `*`, etc.).
    * `FLOAT_MATH` - Float mathematical operation.
    * `ARRAY_INDEX` - Index of an array.
    * `ANY` - Any operation.
* The `direct_use_only` tells the indexer on whether it should only consider the closest operation. For example, `some_var = other_var * 0xfe` with a `direct_use_only` set to `True` and `type_of_use` with only `ASSIGNMENTS` will NOT BE MARKED! Such setup will only mark occurrences such as `some_var = 0xfe`. If you want to match the first case as well, set the `direct_use_only` to `False`.
